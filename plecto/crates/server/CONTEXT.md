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
fast path が一致リクエストを転送する名前付きバックエンド。1 つ以上の **upstream instance** から成り、fast path
は転送時に healthy な instance を round-robin で 1 つ選ぶ（ADR 000017）。route は upstream を名前で指す。plain
HTTP/1.1 で転送する（upstream TLS は後続）。
_Avoid_: backend pool（pool ではなく instance 群で表す）, origin（CDN 文脈の語）

**Prefix strip（host-native rewrite）**:
route が宣言する path 書き換え。fast path が**転送直前**に適用し、chain は元 path を見たまま upstream は
書き換え後を受ける。フィルタ駆動の path 書き換え（WIT `set-path`）とは別物で、契約変更を要さない。
_Avoid_: filter rewrite（フィルタ駆動の書換は別レイヤ・後続）

## ロードバランシング / health（ADR 000017）

**Upstream instance**:
upstream を構成する 1 つの `host:port`。active health check が healthy / unhealthy を切り替え、unhealthy な
instance は分配集合から外れる（eject）。起動時は pessimistic（unhealthy）で始まり、最初の成功 probe で healthy に
昇格する。
_Avoid_: endpoint（Envoy 用語）, backend（曖昧）, wasmtime の instance（別 context・extension plane 側の語）

**Active health check**:
background タスクが各 upstream instance を health の probe path へ定期 probe し、連続成功 / 失敗が閾値に達したら
healthy / unhealthy を切り替える先回り検知。落ちた instance を**実リクエストが踏む前に**避ける。
_Avoid_: liveness probe（k8s 用語）, ping（多義）

**Passive ejection**:
実リクエストの転送失敗（接続失敗 / timeout）を active と**同じ health 状態**に反映し、instance を demote する補完
信号。active が先回り検知、passive が取りこぼしを拾う。引き金になったリクエスト自体は救済しない（retry しない）。
_Avoid_: outlier detection（独立サブシステムを含意。ここでは active と単一状態機を共有）

**Round-robin LB**:
healthy な upstream instance 集合を巡回選択する分配。eject された instance は集合から外れ、復帰（restore）で戻る。
_Avoid_: balancing pool（曖昧）

**No-healthy fail-closed**:
ある upstream の全 instance が unhealthy のとき、upstream に流さず 503 を返す挙動。fail-closed テネットの upstream
版（404 no-route / 502 upstream-error とは別の fault）。
_Avoid_: circuit break（別概念）

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

**Forwarding header family**:
クライアントが送信元 IP / scheme を表すために送りうる一群のヘッダ（`Forwarded` ＋ de-facto の `X-Forwarded-*`、
および `X-Real-IP` / `CF-Connecting-IP` などの client-IP ヘッダ）。いずれもクライアントが自由に書けるため
untrusted。fast path はこの family を**一つの単位**として扱う（ADR 000018 / 000022）。
_Avoid_: XFF（family の一員に過ぎず全体を指さない）, proxy headers（hop-by-hop と紛らわしい）

**Client-IP 伝播（edge モデル）**:
fast path が受信した **forwarding header family を信頼せず剥がし**、自分が観測した接続 peer と接続 scheme から
付け直す既定の姿勢。チェーン実行の**前**に行うので、IP ベースの判断をするフィルタも upstream も Plecto が
確定した値だけを見る。前段に信頼できる LB を置き受信値を信頼ホップ分**尊重して追記**する **trusted-proxy
モデル**は対の姿勢で、後続の設定 knob（ADR 000018 / 000022）。
_Avoid_: XFF passthrough（受信値を信頼する別姿勢）, spoof guard（機構名であって姿勢を表さない）

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
