`gotty_client.nim` を上から順に説明するにゃ。全体は「接続する → 端末を生モードにする → 3つの非同期処理を同時に走らせる → 終わったら後始末」という流れにゃ。

## 0. 全体像

```
main
 └ connectLoop      … 再試行・バックオフ・終了コード
     ├ fetchAuthToken … auth_token.js からトークン取得(HTTP)
     ├ connectWs      … TCP/TLS接続 + WebSocketハンドシェイク
     └ runSession     … 1回の接続中の処理
         ├ onStdin       … キー入力 → 送信キュー
         ├ receiveLoop   … 受信フレーム → 画面表示
         ├ pingLoop      … 10秒ごとにping
         ├ resizeLoop    … 端末サイズ変化の検知
         └ pump          … 送信キューを1本ずつ送る(書き込みは常にここだけ)
```

シングルスレッドの `asyncdispatch` 1本で全部を回すにゃ。Python版の `asyncio` と同じ発想にゃ。

## 1. import と定数

- 標準ライブラリだけで書いてあるにゃ(`re` や `checksums` は不要)。
- `posix` は `read` や `errno` 用、`termios` は生モード用にゃ。
- `ExitKey = 0x1d` が Ctrl+] にゃ。
- `PingIntervalMs`、`ConnectTimeoutMs` などはタイムアウトや間隔の設定にゃ。
- `OpText`、`OpClose` などはWebSocketのopcode(RFC 6455)にゃ。

## 2. 型

| 型 | 役割 |
|---|---|
| `AuthError` | 認証失敗。**再試行しても無駄**なエラーを区別するための例外にゃ |
| `Args` | コマンドライン引数にゃ |
| `EndKind` | セッションの終わり方(ユーザー終了・サーバ正常終了・エラー)にゃ |
| `Session` | 1接続ぶんの状態(ソケット・送信キュー・完了Future・UTF-8の持ち越しバッファ)にゃ |
| `Frame` | 受信したWebSocketフレーム1個(fin, opcode, payload)にゃ |

`Session.done` は `Future[void]` にゃ。これが完了すると `runSession` が先に進んで後始末に入るにゃ。

## 3. ログ(`logErr` / `debugPrint`)

生モード中は出力の改行変換が無効になるので、`\n` だけだと表示が階段状になるにゃ。`rawActive` のときは `\r\n` を使うようにしてあるにゃ。Python版の `debug_print` と同じ理由にゃ。

## 4. 生モード(`enterRaw` / `leaveRaw`)

```nim
tcGetAttr(0, addr origTermios)   # 元の設定を保存
raw.c_lflag = raw.c_lflag and not (ECHO or ICANON or IEXTEN or ISIG)
...
tcSetAttr(0, TCSAFLUSH, addr raw)
```

- Pythonの `tty.setraw` と同じフラグ操作にゃ。エコー・行編集・シグナル生成(Ctrl+C など)を切って、1バイトずつ読めるようにするにゃ。
- そのため **Ctrl+C はリモートに素通し**になるにゃ。
- `leaveRaw` は元の設定を書き戻すにゃ。`addExitProc` にも登録してあるので、どんな終わり方でも端末が壊れにくいにゃ。

## 5. SHA-1 とフレーム処理

### `sha1Raw` / `computeAccept`
ハンドシェイクで、サーバの `Sec-WebSocket-Accept` が正しいか検証するのに使うにゃ。`key + 固定GUID` のSHA-1をbase64にした値が期待値にゃ。外部ライブラリを避けるために自前実装にしたにゃ(前回のコンパイル確認で、実際にハンドシェイクが通ったので正しく動いているにゃ)。

### `buildFrame`(送信)
クライアントからのフレームは **必ずマスクする**決まりにゃ。

1. 先頭バイト: `FIN=1` + opcodeにゃ。
2. 長さ: 125以下は1バイト、65535以下は `126` + 2バイト、それ以上は `127` + 8バイトにゃ。
3. 4バイトのランダムなマスクキーを入れて、payloadを XOR するにゃ。

### `recvExact`(受信の基本)
`sock.recv(n)` は n バイト揃う保証がなく、途中で返ってくることがあるにゃ。そこで、揃うまでループする関数にしてあるにゃ。0バイトが返ったら接続が閉じたとみなして例外にゃ。

### `readFrame`(受信)
2バイトのヘッダを読んで、長さ(126/127なら拡張長)、マスクキー(サーバ→クライアントは通常なし)、payload の順に読むにゃ。64MBを超える長さは拒否するにゃ。

## 6. 認証トークンとハンドシェイク

### `fetchAuthToken`
- URLは「WSのパスのディレクトリ + `auth_token.js`」にゃ(例: `/abc/ws` → `/abc/auth_token.js`)。Python版の `urljoin` と同じにゃ。
- 401は `AuthError`(再試行しない)にゃ。
- 404や接続失敗は、認証情報を渡していなければ「認証なし」で続行するにゃ。認証情報があるのに失敗なら、エラーにするにゃ。
- 本文から `var gotty_auth_token = '...'` を文字列検索で取り出すにゃ(正規表現は使っていないにゃ)。

### `handshake`
1. TCP接続にゃ。
2. `wss` なら `wrapConnectedSocket` でTLS化するにゃ。ここでホスト名を渡すので、**SNIと証明書の名前検証**が働くにゃ(Cloudflare Tunnel向けにゃ)。
3. `GET ... Upgrade: websocket` を送るにゃ(改行は必ず `\r\n`)。Basic認証があれば `Authorization` も付けるにゃ。
4. 応答を **1バイトずつ**読むにゃ。これは、ヘッダの直後に来るWebSocketのデータを読み過ぎて捨てないためにゃ。
5. `101` の確認と、`Sec-WebSocket-Accept` の検証をするにゃ(ヘッダ名は大文字小文字を無視)。

### `connectWs`
`handshake` を `withTimeout` で包んで、10秒で打ち切るにゃ。失敗したらソケットを閉じるにゃ。

## 7. セッションの中身

### 送信キュー(`enqueue` / `pump`)
ping・キー入力・リサイズが同じソケットに同時に書くと、フレームが混ざる危険があるにゃ。そこで、

- みんなが `enqueue` でキューに積むにゃ。
- `pump` が1本だけ走って、順番に `send` するにゃ。

という作りにしたにゃ。`sending` フラグで「pumpが走っているか」を管理するにゃ。

### `finish`
セッションの終わりを1回だけ記録して `done` を完了させるにゃ。複数の場所から呼ばれても安全にゃ。

### 入力側(`onStdin`)
`addRead` のコールバックにゃ。stdinが読める状態のときだけ呼ばれるので、`read` でブロックしないにゃ。

- `0x1d`(Ctrl+])が含まれていたら、ユーザー終了にゃ。
- 受け取ったバイトを `pending` に足して、`utf8CompleteLen` で「最後の中途半端なマルチバイト文字」を除いた分だけ送るにゃ。
- 日本語がチャンクの境目で切れても、次回に持ち越すので文字化けしにくいにゃ。
- 送るときは `"1" + 入力` のtextフレームにゃ(GoTTYの入力メッセージ)。

### 受信側(`receiveLoop` / `handleMessage`)
- opcodeごとに処理するにゃ。
  - Close: コードが1000/1001/1005なら静かに終了、それ以外は失敗にゃ。
  - Ping: Pongを返すにゃ。
  - Text/Binary/Continuation: 断片化に対応して、finが立ったら1メッセージとして処理にゃ。
- `handleMessage` はGoTTYの種別で分岐するにゃ。
  - `'1'`: base64をデコードして、そのまま標準出力に書くにゃ(端末のエスケープシーケンスもそのまま通るにゃ)。
  - `'3'`: ウィンドウタイトルをエスケープシーケンスで設定にゃ。
  - `'2'/'4'/'5'`: デバッグ表示だけにゃ。

### `pingLoop` と `resizeLoop`
- ping: 10秒ごとに `"2"` を送るにゃ。
- resize: 0.5秒ごとにサイズを見て、変わっていれば `"3"` + JSON(`columns`/`rows`)を送るにゃ。`addSignal` はAndroidで使えないので、ポーリングにしたにゃ。

## 8. `runSession`(1接続の司令塔)

```
enterRaw()
最初のメッセージ(素のJSON: {"AuthToken":...} か {})を積む
サイズ送信
stdinを登録して addRead
receiveLoop / pingLoop / resizeLoop を起動
await s.done          ← どれかが finish するまで待つ
finally: stdin解除 → closeフレーム(できれば) → ソケットclose → leaveRaw → 「Disconnected」表示
```

- **最初のメッセージは型プレフィックスなしのJSON**にゃ。GoTTYの仕様で、トークンがなくても `{}` を送るにゃ(これがないとサーバが待ち続けるにゃ)。
- `finally` なので、エラーでも必ず端末を戻すにゃ。

## 9. `connectLoop`(再試行の制御)

1. 毎回、トークンを取り直して接続するにゃ(期限切れ対策、Python版と同じ)。
2. セッションの終わり方で分岐するにゃ。
   - ユーザー終了: 終了コード0にゃ。`--reconnect` 指定でも抜けられるにゃ。
   - サーバが正常終了: 0で終了にゃ(`--reconnect` なら2秒後に再接続)。
   - エラー: 例外にして、再試行ルートに入るにゃ。
3. `AuthError` は即終了(コード1)にゃ。それ以外は 1s → 2s → 4s…(上限30秒)で待って再試行にゃ。最大回数に達したらコード1にゃ。

## 10. CLI(`parseArgs` / `main`)

- `std/parseopt` で `--url=...` を解析するにゃ。以前のNim版にあった「最後の引数を落とすバグ」は、これで解消にゃ。
- パスワードは環境変数 `GOTTY_PASSWORD` でも渡せるにゃ(プロセス一覧に出さないためにゃ)。
- 不明な引数は、使い方を表示して終了コード2にゃ。
- `isatty(stdin)` を確認してから始めるにゃ。

## 設計のポイントまとめ

| 以前の問題 | 今の対処 |
|---|---|
| スレッドで状態が共有されない | スレッドをやめて `addRead` にゃ |
| 同時送信でフレームが混ざる | 送信キュー + pump 1本にゃ |
| 途中までしか読めない | `recvExact` にゃ |
| ユーザー終了で再接続してしまう | `EndKind` で区別にゃ |
| 端末が壊れる | `finally` + `addExitProc` にゃ |

