# GoTTY WebSocket terminal client (Unix only) -- Nim port of the Python client.
#
# Build:  nim c -d:ssl -d:release --mm:orc gotty_client.nim     (Nim 2.x)
#         nim c -d:ssl -d:release gotty_client.nim              (Nim 1.6)
#
# GoTTY protocol (text frames)
#   Client -> Server: '1' Input, '2' Ping, '3' ResizeTerminal
#   Server -> Client: '1' Output (base64), '2' Pong, '3' SetWindowTitle,
#                     '4' SetPreferences, '5' SetReconnect
#   The first client message is plain JSON: {"AuthToken": "..."}
#
# Exit the local client with Ctrl+]  (Ctrl+C / Ctrl+D go to the remote shell).
#
# Design notes
#   * single-threaded: stdin is watched with asyncdispatch.addRead (no threads)
#   * all socket writes go through one queue, so frames never interleave
#   * terminal resize is detected by polling (works on Android/Termux too)
#   * raw mode saves/restores the original termios settings

import std/[asyncdispatch, asyncnet, httpclient, net, os, strutils, uri, json,
            base64, deques, parseopt, terminal, sysrand]
import std/posix
import termios
import std/exitprocs

const
  DefaultUrl = "ws://localhost:8080/ws"
  ExitKey = 0x1d'u8                 # Ctrl+]
  ConnectTimeoutMs = 10_000
  AuthTimeoutMs = 5_000
  PingIntervalMs = 10_000
  ReconnectDelaySec = 2
  MaxPayload = 64 * 1024 * 1024

  ResizeCheckMs = 500               # terminal size polling (addSignal is missing on Android/Termux)

  OpCont = 0x0
  OpText = 0x1
  OpBinary = 0x2
  OpClose = 0x8
  OpPing = 0x9
  OpPong = 0xA

type
  AuthError = object of CatchableError

  Args = object
    url, username, password: string
    retries: int
    reconnect, insecure, debug: bool

  EndKind = enum ekNone, ekUserQuit, ekServerClosed, ekError

  Session = ref object
    sock: AsyncSocket
    outq: Deque[string]
    sending, closed: bool
    done: Future[void]
    endKind: EndKind
    endMsg: string
    pending: string               # incomplete UTF-8 tail of stdin

  Frame = object
    fin: bool
    op: int
    payload: string

var
  debugOn = false
  rawActive = false
  origTermios: Termios

# ---------------------------------------------------------------- logging

proc logErr(msg: string) =
  # raw mode disables output post-processing, so '\n' alone staircases
  stderr.write(msg, if rawActive: "\r\n" else: "\n")
  stderr.flushFile()

proc debugPrint(msg: string) =
  if debugOn: logErr("[DEBUG] " & msg)

# ---------------------------------------------------------------- raw tty

proc leaveRaw() {.noconv.} =
  if rawActive:
    rawActive = false
    discard tcSetAttr(0, TCSADRAIN, addr origTermios)

proc enterRaw() =
  if tcGetAttr(0, addr origTermios) != 0:
    raise newException(OSError, "tcgetattr failed (stdin is not a TTY?)")
  var raw = origTermios
  raw.c_iflag = raw.c_iflag and not (BRKINT or ICRNL or INPCK or ISTRIP or IXON)
  raw.c_oflag = raw.c_oflag and not OPOST
  raw.c_cflag = (raw.c_cflag and not (CSIZE or PARENB)) or CS8
  raw.c_lflag = raw.c_lflag and not (ECHO or ICANON or IEXTEN or ISIG)
  raw.c_cc[VMIN] = 1.char
  raw.c_cc[VTIME] = 0.char
  if tcSetAttr(0, TCSAFLUSH, addr raw) != 0:
    raise newException(OSError, "tcsetattr failed")
  rawActive = true

# ---------------------------------------------------------------- SHA-1 (for Sec-WebSocket-Accept)

proc rol(x: uint32, n: int): uint32 = (x shl n) or (x shr (32 - n))

proc sha1Raw(s: string): string =
  var
    h0 = 0x67452301'u32
    h1 = 0xEFCDAB89'u32
    h2 = 0x98BADCFE'u32
    h3 = 0x10325476'u32
    h4 = 0xC3D2E1F0'u32
    msg = s
  msg.add '\x80'
  while msg.len mod 64 != 56: msg.add '\0'
  let bits = uint64(s.len) * 8
  for i in countdown(7, 0): msg.add char((bits shr (i * 8)) and 0xFF)

  for chunk in countup(0, msg.len - 1, 64):
    var w: array[80, uint32]
    for i in 0 ..< 16:
      let o = chunk + i * 4
      w[i] = (uint32(ord(msg[o])) shl 24) or (uint32(ord(msg[o + 1])) shl 16) or
             (uint32(ord(msg[o + 2])) shl 8) or uint32(ord(msg[o + 3]))
    for i in 16 ..< 80:
      w[i] = rol(w[i - 3] xor w[i - 8] xor w[i - 14] xor w[i - 16], 1)
    var a = h0; var b = h1; var c = h2; var d = h3; var e = h4
    for i in 0 ..< 80:
      var f, k: uint32
      if i < 20:   f = (b and c) or ((not b) and d); k = 0x5A827999'u32
      elif i < 40: f = b xor c xor d;                k = 0x6ED9EBA1'u32
      elif i < 60: f = (b and c) or (b and d) or (c and d); k = 0x8F1BBCDC'u32
      else:        f = b xor c xor d;                k = 0xCA62C1D6'u32
      let t = rol(a, 5) + f + e + k + w[i]
      e = d; d = c; c = rol(b, 30); b = a; a = t
    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e

  for h in [h0, h1, h2, h3, h4]:
    for i in countdown(3, 0): result.add char((h shr (i * 8)) and 0xFF)

proc computeAccept(key: string): string =
  base64.encode(sha1Raw(key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))

# ---------------------------------------------------------------- WebSocket frames

proc randomBytes(n: int): string =
  for b in urandom(n): result.add char(b)

proc buildFrame(op: int, payload: string): string =
  ## Client frames must be masked (RFC 6455).
  let key = randomBytes(4)
  let n = payload.len
  result = newStringOfCap(n + 14)
  result.add char(0x80 or op)
  if n <= 125:
    result.add char(0x80 or n)
  elif n <= 0xFFFF:
    result.add char(0x80 or 126)
    result.add char((n shr 8) and 0xFF)
    result.add char(n and 0xFF)
  else:
    result.add char(0x80 or 127)
    for i in countdown(7, 0): result.add char((n shr (i * 8)) and 0xFF)
  result.add key
  for i in 0 ..< n:
    result.add char(byte(payload[i]) xor byte(key[i and 3]))

proc recvExact(sock: AsyncSocket, n: int): Future[string] {.async.} =
  ## recv(n) may return fewer than n bytes, so loop.
  var buf = newStringOfCap(n)
  while buf.len < n:
    let chunk = await sock.recv(n - buf.len)
    if chunk.len == 0:
      raise newException(IOError, "connection closed by peer")
    buf.add chunk
  return buf

proc readFrame(sock: AsyncSocket): Future[Frame] {.async.} =
  let h = await recvExact(sock, 2)
  let b0 = ord(h[0])
  let b1 = ord(h[1])
  var n = b1 and 0x7F
  if n == 126:
    let e = await recvExact(sock, 2)
    n = (ord(e[0]) shl 8) or ord(e[1])
  elif n == 127:
    let e = await recvExact(sock, 8)
    if ord(e[0]) >= 0x80:
      raise newException(IOError, "frame too large")
    n = 0
    for c in e: n = (n shl 8) or ord(c)
  if n > MaxPayload:
    raise newException(IOError, "frame too large: " & $n)

  var maskKey = ""
  if (b1 and 0x80) != 0:
    maskKey = await recvExact(sock, 4)
  var payload = ""
  if n > 0:
    payload = await recvExact(sock, n)
  if maskKey.len == 4:
    for i in 0 ..< payload.len:
      payload[i] = char(byte(payload[i]) xor byte(maskKey[i and 3]))
  return Frame(fin: (b0 and 0x80) != 0, op: b0 and 0x0F, payload: payload)

# ---------------------------------------------------------------- handshake / auth

proc basicAuthHeader(user, pass: string): string =
  if user != "" and pass != "": "Basic " & base64.encode(user & ":" & pass) else: ""

proc fetchAuthToken(wsUrl, authHeader: string, hasCreds, insecure: bool): Future[string] {.async.} =
  ## <ws path dir>/auth_token.js, same as the Python version. "" = no token.
  let u = parseUri(wsUrl)
  let scheme = if u.scheme == "wss": "https" else: "http"
  var dir = "/"
  if u.path.len > 0:
    let i = u.path.rfind('/')
    if i >= 0: dir = u.path[0 .. i]
  let hostPort = u.hostname & (if u.port != "": ":" & u.port else: "")
  let url = scheme & "://" & hostPort & dir & "auth_token.js"
  debugPrint("Fetching auth token from: " & url)

  when defined(ssl):
    var client =
      if insecure: newAsyncHttpClient(sslContext = newContext(verifyMode = CVerifyNone))
      else: newAsyncHttpClient()
  else:
    var client = newAsyncHttpClient()
  if authHeader != "":
    client.headers = newHttpHeaders({"Authorization": authHeader})

  var body = ""
  try:
    try:
      let fut = client.get(url)
      if not await withTimeout(fut, AuthTimeoutMs):
        raise newException(IOError, "auth_token.js request timed out")
      let resp = fut.read()
      if resp.code == Http401:
        raise newException(AuthError, "HTTP 401 Unauthorized - check credentials")
      if resp.code == Http404 and not hasCreds:
        debugPrint("auth_token.js not found - assuming no auth")
        return ""
      if not resp.code.is2xx:
        raise newException(IOError, "auth_token.js returned " & $resp.code)
      body = await resp.body
    except AuthError:
      raise
    except CatchableError as e:
      if not hasCreds:
        debugPrint("auth_token.js unavailable (" & e.msg & ") - assuming no auth")
        return ""
      raise newException(IOError, "Failed to fetch auth token: " & e.msg)
  finally:
    client.close()

  const marker = "var gotty_auth_token = '"
  let i = body.find(marker)
  if i < 0:
    debugPrint("No auth token in response")
    return ""
  let st = i + marker.len
  let en = body.find('\'', st)
  if en < 0: return ""
  debugPrint("Auth token fetched")
  return body[st ..< en]

proc handshake(sock: AsyncSocket, u: Uri, authHeader: string, insecure: bool) {.async.} =
  let secure = u.scheme == "wss"
  let port = if u.port != "": Port(parseInt(u.port)) else: Port(if secure: 443 else: 80)
  await sock.connect(u.hostname, port)

  if secure:
    when defined(ssl):
      let ctx = newContext(verifyMode = if insecure: CVerifyNone else: CVerifyPeer)
      # hostname => SNI (needed behind Cloudflare) + certificate name check
      wrapConnectedSocket(ctx, sock, handshakeAsClient, u.hostname)
    else:
      raise newException(IOError, "wss:// needs a build with -d:ssl")

  let key = base64.encode(randomBytes(16))
  let hostHdr = u.hostname & (if u.port != "": ":" & u.port else: "")
  var path = if u.path == "": "/" else: u.path
  if u.query != "": path.add "?" & u.query
  var req = "GET " & path & " HTTP/1.1\r\n" &
            "Host: " & hostHdr & "\r\n" &
            "Upgrade: websocket\r\n" &
            "Connection: Upgrade\r\n" &
            "Sec-WebSocket-Key: " & key & "\r\n" &
            "Sec-WebSocket-Version: 13\r\n"
  if authHeader != "": req.add "Authorization: " & authHeader & "\r\n"
  req.add "\r\n"
  await sock.send(req)

  # Read byte by byte so no WebSocket data after the headers is swallowed.
  var resp = ""
  while not resp.endsWith("\r\n\r\n"):
    let c = await sock.recv(1)
    if c.len == 0: raise newException(IOError, "handshake: connection closed")
    resp.add c
    if resp.len > 16384: raise newException(IOError, "handshake: response too large")

  let lines = resp.split("\r\n")
  let status = lines[0].splitWhitespace()
  if status.len < 2 or status[1] != "101":
    raise newException(IOError, "WS handshake failed: " & lines[0])
  var accept = ""
  for l in lines[1 .. ^1]:
    let i = l.find(':')
    if i > 0 and l[0 ..< i].strip().toLowerAscii() == "sec-websocket-accept":
      accept = l[i + 1 .. ^1].strip()
  if accept != computeAccept(key):
    raise newException(IOError, "Invalid Sec-WebSocket-Accept")

proc connectWs(url, authHeader: string, insecure: bool): Future[AsyncSocket] {.async.} =
  let u = parseUri(url)
  if u.scheme notin ["ws", "wss"]:
    raise newException(AuthError, "URL must start with ws:// or wss://")  # not retried
  let sock = newAsyncSocket()
  try:
    let fut = handshake(sock, u, authHeader, insecure)
    if not await withTimeout(fut, ConnectTimeoutMs):
      raise newException(IOError, "connect timed out")
    fut.read()                     # re-raise handshake errors
  except CatchableError:
    sock.close()
    raise
  return sock

# ---------------------------------------------------------------- session

proc newSession(sock: AsyncSocket): Session =
  Session(sock: sock, outq: initDeque[string](), done: newFuture[void]("session"))

proc finish(s: Session, kind: EndKind, msg = "") =
  if s.closed: return
  s.closed = true
  s.endKind = kind
  s.endMsg = msg
  s.done.complete()

proc pump(s: Session) {.async.} =
  s.sending = true
  try:
    while s.outq.len > 0 and not s.closed:
      let frame = s.outq.popFirst()
      await s.sock.send(frame)
  except CatchableError as e:
    s.finish(ekError, "send failed: " & e.msg)
  finally:
    s.sending = false

proc enqueue(s: Session, frame: string) =
  ## One writer at a time => frames from ping/input/resize never interleave.
  s.outq.addLast frame
  if not s.sending and not s.closed:
    asyncCheck pump(s)

proc sendText(s: Session, payload: string) =
  s.enqueue buildFrame(OpText, payload)

proc sendSize(s: Session) =
  try:
    let (w, h) = terminalSize()
    if w > 0 and h > 0:
      s.sendText("3" & $(%*{"columns": w, "rows": h}))
      debugPrint("-> Resize: " & $w & "x" & $h)
  except CatchableError as e:
    debugPrint("Failed to get terminal size: " & e.msg)

proc utf8CompleteLen(s: string): int =
  ## Length of s without a trailing, still incomplete multibyte character.
  var i = s.len - 1
  var back = 0
  while i >= 0 and back < 4 and (ord(s[i]) and 0xC0) == 0x80:
    dec i
    inc back
  if i < 0 or (ord(s[i]) and 0xC0) == 0x80: return s.len
  let c = ord(s[i])
  let need = if c >= 0xF0: 4 elif c >= 0xE0: 3 elif c >= 0xC0: 2 else: 1
  if need > 1 and back + 1 < need: i else: s.len

proc onStdin(s: Session): bool =
  var buf: array[1024, byte]
  let n = posix.read(0, addr buf[0], buf.len)
  if n < 0:
    if errno == EINTR or errno == EAGAIN: return false
    s.finish(ekError, "stdin read error")
    return true
  if n == 0:
    debugPrint("EOF on stdin")
    s.finish(ekUserQuit)
    return true
  for i in 0 ..< n:
    if buf[i] == ExitKey:
      debugPrint("Exit key (Ctrl+]) pressed")
      s.finish(ekUserQuit)
      return true
  for i in 0 ..< n: s.pending.add char(buf[i])
  let k = utf8CompleteLen(s.pending)
  if k > 0:
    s.sendText("1" & s.pending[0 ..< k])
    s.pending = s.pending[k .. ^1]
  return false

proc handleMessage(msg: string) =
  if msg.len == 0: return
  let body = msg[1 .. ^1]
  case msg[0]
  of '1':                          # Output (base64)
    try:
      let decoded = base64.decode(body)
      if decoded.len > 0:
        discard stdout.writeBuffer(unsafeAddr decoded[0], decoded.len)
        stdout.flushFile()
    except ValueError as e:
      debugPrint("Failed to decode base64 output: " & e.msg)
  of '2': debugPrint("<- Pong")
  of '3':                          # SetWindowTitle (plain text)
    stdout.write("\e]0;" & body & "\a")
    stdout.flushFile()
  of '4': debugPrint("<- SetPreferences: " & body[0 ..< min(body.len, 200)])
  of '5': debugPrint("<- SetReconnect: " & body[0 ..< min(body.len, 50)])
  else: debugPrint("<- Unknown message type: " & $msg[0])

proc receiveLoop(s: Session) {.async.} =
  var msgOp = -1
  var msgBuf = ""
  try:
    while not s.closed:
      let f = await readFrame(s.sock)
      case f.op
      of OpClose:
        let code = if f.payload.len >= 2: (ord(f.payload[0]) shl 8) or ord(f.payload[1]) else: 1005
        debugPrint("<- Close frame (code " & $code & ")")
        # like Python's `async for`: 1000/1001 end quietly, anything else is a failure
        if code in [1000, 1001, 1005]: s.finish(ekServerClosed)
        else: s.finish(ekError, "server closed connection (code " & $code & ")")
        return
      of OpPing:
        s.enqueue buildFrame(OpPong, f.payload)
      of OpPong:
        debugPrint("<- WS Pong")
      of OpText, OpBinary, OpCont:
        if f.op == OpCont:
          if msgOp < 0: raise newException(IOError, "unexpected continuation frame")
          msgBuf.add f.payload
        else:
          msgOp = f.op
          msgBuf = f.payload
        if f.fin:
          handleMessage(msgBuf)
          msgBuf = ""
          msgOp = -1
      else:
        debugPrint("Ignored control frame: 0x" & toHex(f.op, 2))
  except CatchableError as e:
    s.finish(ekError, e.msg)

proc pingLoop(s: Session) {.async.} =
  while not s.closed:
    await sleepAsync(PingIntervalMs)
    if s.closed: break
    s.sendText("2")

proc resizeLoop(s: Session) {.async.} =
  ## Portable replacement for a SIGWINCH handler: poll the size, send on change.
  var last = (w: 0, h: 0)
  try: last = terminalSize()
  except CatchableError: discard
  while not s.closed:
    await sleepAsync(ResizeCheckMs)
    if s.closed: break
    try:
      let cur = terminalSize()
      if cur != last:
        last = cur
        s.sendSize()
    except CatchableError: discard

proc runSession(sock: AsyncSocket, token: string): Future[Session] {.async.} =
  let s = newSession(sock)
  enterRaw()
  var stdinReg = false
  try:
    # First message: plain JSON, no type prefix
    s.sendText(if token != "": $(%*{"AuthToken": token}) else: "{}")
    s.sendSize()

    proc stdinCb(fd: AsyncFD): bool = onStdin(s)
    register(AsyncFD(0))
    stdinReg = true
    addRead(AsyncFD(0), stdinCb)

    asyncCheck receiveLoop(s)
    asyncCheck pingLoop(s)
    asyncCheck resizeLoop(s)
    await s.done
  finally:
    if not s.closed:
      s.closed = true
      if s.endKind == ekNone: s.endKind = ekError
    if stdinReg: unregister(AsyncFD(0))
    if not s.sending:                 # best-effort close handshake
      try: await sock.send(buildFrame(OpClose, "\x03\xe8"))
      except CatchableError: discard
    sock.close()
    leaveRaw()
    logErr("\n🔌 Disconnected. Terminal restored.")
  return s

# ---------------------------------------------------------------- main loop

proc connectLoop(args: Args): Future[int] {.async.} =
  let authHeader = basicAuthHeader(args.username, args.password)
  let hasCreds = authHeader != ""
  let maxTries = if args.reconnect: high(int) else: max(1, args.retries)
  var attempt = 0
  while attempt < maxTries:
    inc attempt
    try:
      # re-fetch every time: tokens may expire between attempts
      let token = await fetchAuthToken(args.url, authHeader, hasCreds, args.insecure)
      let sock = await connectWs(args.url, authHeader, args.insecure)
      logErr("✅ Connected to " & args.url & "  (exit: Ctrl+])")
      if args.reconnect: attempt = 0
      let s = await runSession(sock, token)
      case s.endKind
      of ekUserQuit: return 0
      of ekServerClosed:
        if not args.reconnect: return 0
        logErr("Reconnecting in " & $ReconnectDelaySec & "s...")
        await sleepAsync(ReconnectDelaySec * 1000)
      else:
        raise newException(IOError, s.endMsg)
    except AuthError as e:
      logErr("❌ Error: " & e.msg)
      return 1                         # retrying will not help
    except CatchableError as e:
      if attempt >= maxTries:
        logErr("\n❌ Failed after " & $attempt & " attempts: " & e.msg)
        return 1
      let wait = min(30, 1 shl (attempt - 1))
      logErr("\n⚠️  Attempt " & $attempt & "/" & $maxTries & " failed: " & e.msg)
      logErr("   Retrying in " & $wait & "s...")
      await sleepAsync(wait * 1000)
  return 1

# ---------------------------------------------------------------- CLI

const UsageText = """
GoTTY WebSocket Client
Usage: gotty_client [options]

Options:
  --url=ws://...        WebSocket URL (default: ws://localhost:8080/ws)
  --username=user       Basic auth username
  --password=pass       Basic auth password (or env GOTTY_PASSWORD)
  --retries=N           Max connection attempts with backoff (default: 3)
  --reconnect           Reconnect forever (Ctrl+] still quits)
  --insecure            Do not verify TLS certificates
  --debug               Enable debug output
  --help                Show this help

Exit the client with Ctrl+]
"""

proc die(msg: string) =
  stderr.writeLine msg
  stderr.writeLine UsageText
  quit(2)

proc parseArgs(): Args =
  result.url = DefaultUrl
  result.retries = 3
  result.password = getEnv("GOTTY_PASSWORD")
  var p = initOptParser(commandLineParams(),
                        longNoVal = @["reconnect", "insecure", "debug", "help"])
  for kind, key, val in p.getopt():
    case kind
    of cmdLongOption:
      case key
      of "url": result.url = val
      of "username": result.username = val
      of "password": result.password = val
      of "retries":
        try: result.retries = parseInt(val)
        except ValueError: die("Invalid --retries: " & val)
      of "reconnect": result.reconnect = true
      of "insecure": result.insecure = true
      of "debug": result.debug = true
      of "help":
        stdout.write UsageText
        quit(0)
      else: die("Unknown option: --" & key)
    else:
      die("Unknown argument: " & key)

when isMainModule:
  let args = parseArgs()
  debugOn = args.debug
  if not isatty(stdin):
    logErr("❌ stdin is not a TTY.")
    quit(1)
  addExitProc(leaveRaw)              # terminal gets restored whatever happens
  var code = 1
  try:
    code = waitFor connectLoop(args)
  except CatchableError as e:
    leaveRaw()
    logErr("❌ Error: " & e.msg)
  quit(code)
