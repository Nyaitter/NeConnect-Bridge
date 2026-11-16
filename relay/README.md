# 協力者用ブリッジ

自分の環境で中継を動かし、公開した URL を公式のブリッジに登録するためのプログラムです。
公式のブリッジへそのまま取り次ぎます。

## 起動

Node.js 22 以上を用意します。

```bash
node relay/index.js --relay-target https://example.com --listen :8090
```

`--relay-target` には公式のブリッジの URL を指定します。

## 1つのファイルにまとめる

```bash
node tools/build-server-package.mjs --target https://example.com --out nctb-server
```

作った `nctb-server` は次のように起動できます。

```bash
./nctb-server --relay --listen :8090
```

## 公開と登録

起動した中継を外部から届く URL で公開し、ホームの「協力する」から登録します。登録にはサインインが必要です。
