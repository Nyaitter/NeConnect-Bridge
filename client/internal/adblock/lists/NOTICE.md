# 一覧の出どころと条件

`domains.txt.gz` は、次の公開一覧から広告・追跡の配信元だけを抜き出し、重複を除いて
1つにまとめたものです。生成は `tools/build_lists.py` で行います。

| 一覧 | 配布元 | 条件 |
| --- | --- | --- |
| AdGuard DNS filter | https://github.com/AdguardTeam/AdGuardSDNSFilter | GPL-3.0 |
| AdGuard Japanese filter（広告配信元） | https://github.com/AdguardTeam/AdguardFilters | GPL-3.0 |
| OISD small | https://oisd.nl | GPL-3.0 |

一覧そのものは、それぞれの配布元の条件（GPL-3.0）に従います。このリポジトリの
ライセンスはコードに適用されるもので、一覧の条件を置き換えるものではありません。

止める対象は名前（ドメイン）だけです。道筋や正規表現で指定された規則は、名前だけに
すると広がりすぎるため取り込んでいません。`@@` で始まる除外の指定は、そのまま残して
あります。
