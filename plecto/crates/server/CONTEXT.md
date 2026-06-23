# Fast path — 用語集

接続を受け、TLS を終端し、HTTP を解し、リクエストを route 照合して filter chain を駆動し、upstream へ
転送する native-Rust 側の構成要素（`plecto-server`、ADR 000013）。全体像と他コンテキストとの関係は
[../../../CONTEXT-MAP.md](../../../CONTEXT-MAP.md)。本ファイルは用語集であり、実装詳細・仕様・決定の置き場では
ない（設計判断は `CLAUDE.md` と `docs/ADR/`、契約は `wit/`）。

## ルーティング

**Route**:
1 本の routing 規則。match 基準（host ＋ path prefix）に当たったリクエストを、その route の inline chain で
処理し、指定の upstream へ転送する。fast path はリクエストごとに route を 1 本だけ選ぶ。
_Avoid_: rule（曖昧）, mapping（方向が出ない）

**Route selection（最長一致）**:
リクエストの host と path から route を選ぶ照合。host が一致（または無指定）し path prefix が `/` 境界で
前方一致する route のうち、**最長 prefix** を選ぶ。一致なしは 404。
_Avoid_: dispatch（chain 駆動と紛らわしい）

**Upstream**:
fast path が一致リクエストを転送する名前付きバックエンド（`host:port`）。v0.1 は plain HTTP/1.1・1 route に
1 アドレス（インスタンス間 LB は後続）。
_Avoid_: backend pool（プールは後続概念）, origin（CDN 文脈の語）

**Prefix strip（host-native rewrite）**:
route が宣言する path 書き換え。fast path が**転送直前**に適用し、chain は元 path を見たまま upstream は
書き換え後を受ける。フィルタ駆動の path 書き換え（WIT `set-path`）とは別物で、契約変更を要さない。
_Avoid_: filter rewrite（フィルタ駆動の書換は別レイヤ・後続）

## リクエスト処理

**Opaque body（pass-through）**:
fast path がフィルタに渡さず素通しでストリームするボディ。header-only 契約（ADR 000010）ゆえ、リクエスト
ボディは upstream へ、レスポンスボディはクライアントへ、フィルタを介さず流れる。
_Avoid_: body proxy（変換を含意。ここでは非接触）

**Blocking bridge（sync↔async）**:
async な fast path が **sync な filter chain**（wasmtime の `!Send` Store）を blocking プール上で駆動する
継ぎ目。route 照合は async スレッド、chain 駆動は blocking プール（M1 の trusted instance pool が再利用・
飽和を担う）。
_Avoid_: worker pool（曖昧）, executor（async ランタイム側と紛らわしい）

## TLS

**TLS termination**:
fast path が受理接続を rustls で復号し、以降を平文として扱う処理。upstream への再暗号化（upstream TLS）とは
別。証明書は宣言的 manifest（`[[tls]]`）で静的に与える。
_Avoid_: TLS offload（LB 機器の語感）, SSL（旧称）

**SNI cert selection**:
ハンドシェイクの SNI（接続先 host 名）で提示する証明書を選ぶ仕組み。host 指定証明書に一致しなければ
host-less の default cert に fallback、それも無ければハンドシェイク拒否（fail-closed）。
_Avoid_: vhost（routing 側の語と混同）

**Default cert**:
SNI がどの host 指定証明書にも一致しないときに提示する host 無指定の証明書。無ければ未一致接続は拒否される。
_Avoid_: fallback cert（意味は同じだが用語を一つに固定）

## HTTP

**ALPN negotiation（プロトコル選択）**:
TLS ハンドシェイクの ALPN で h2 / http/1.1 を選ぶ仕組み。fast path は h2 を優先広告し、h2 が選ばれた接続だけ
HTTP/2 で終端する。それ以外（http/1.1・ALPN 未交渉）と平文接続は HTTP/1.1。h2c（平文 HTTP/2）は採らない。
_Avoid_: protocol upgrade（h2c / Upgrade 経路を含意）

**HTTP/2 stream（= 1 トランザクション）**:
h2 接続が多重化する各ストリーム。1 ストリーム = 1 トランザクション = 1 snapshot で、route → chain → forward を
HTTP/1.1 と同一経路で回す。同一接続の並行ストリームが filter chain の並行駆動（M1 プールへの並行 checkout）を
生む最初の局面。
_Avoid_: request（多重化の単位であることが出ない）, channel（h2 用語でない）

**QUIC listener（HTTP/3）**:
TCP とは別に張る UDP 上の listener。QUIC（TLS1.3 必須・ALPN `h3`）でリクエストを受け、TCP スライスと同一の
route → chain → forward へ繋ぐ。TLS が設定されているときだけ有効で、TCP listener と同一ポート番号の UDP に張る。
各 h3 リクエストは 1 つの QUIC bidi stream に対応する。
_Avoid_: HTTP/3 socket（listener の語に統一）, datagram listener（HTTP/3 はストリーム上、QUIC datagram は非採用）

**Alt-Svc advertisement（h3 への誘導）**:
TCP（HTTP/1.1 / HTTP/2）応答に付ける `Alt-Svc: h3=":<port>"` ヘッダ。同一サービスが HTTP/3 でも到達可能だと
クライアントに知らせ、次回接続を h3 へ誘導する（アップグレードではなく発見）。h3 応答自体には付けない。
_Avoid_: HTTP/3 upgrade（Upgrade 機構ではない）, redirect（リダイレクトではない）
