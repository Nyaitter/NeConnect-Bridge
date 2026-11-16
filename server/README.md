# ブリッジサーバー

つながりにくい回線からでも、いつものブラウザを使えるようにするサーバーです。
利用者にはアプリの配布と接続先の案内を返します。

## 用意するもの

- Node.js 22 以上
- 外部から届く URL

## 起動

```bash
npm install --omit=dev
node server/index.js --listen :8090 --obfs :8443 --local-ssh 127.0.0.1:22
```

ブラウザで `/bridge` を開きます。

## 設定

`nctb.env` に書くか、起動時の指定で渡します。

| 名前 | 内容 |
|---|---|
| `NCTB_AUTH_API` | サインインの問い合わせ先 |
| `NCTB_SSH_HOST` | 接続先として案内するアドレス |
| `NCTB_OBFS_HOST` | 予備の接続先として案内するアドレス |
| `NCTB_MAX_CLIENTS` | 1つの URL を受け入れる人数 |
| `NCTB_RELEASES` | アプリを置くフォルダ |
| `NCTB_DATA_DIR` | 設定や記録を置くフォルダ |

中継に使う鍵は `e2e_key` と `obfs_secret` に置きます。どちらもサーバーの中だけで読まれます。

## 置かれるファイル

| ファイル | 内容 |
|---|---|
| `bridges.json` | 登録された接続先 |
| `.session_secret` | サインインの記録 |
| `.nyaitter_app_token` | アプリの控え |
| `.admin_token` | 管理コマンドの控え |
| `releases/` | 配布するアプリと協力者用の中継プログラム |

## アプリの配布

`releases/` に `NeConnectBridge-<版>.exe` を置きます。ホームの一覧に版が並び、最新が選ばれた状態で開きます。

## 管理コマンド

サーバーを起動したまま、同じフォルダで実行します。

```bash
node cli.js list
node cli.js status
node cli.js add https://example.com/bridge/server
node cli.js remove https://example.com/bridge/server
node cli.js reset
node cli.js set-max 10
```

## 画面

| 場所 | 内容 |
|---|---|
| `/bridge` | アプリの配布と接続先の案内 |
| `/bridge/dashboard` | 登録した接続先の状態 |
