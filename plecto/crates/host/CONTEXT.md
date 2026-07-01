# Extension plane / host runtime — 用語集

WASM フィルタを安全に実行する wasmtime 埋め込みホスト（`plecto-host`）と、それが fast path に対して守る
`plecto:filter` 型契約のコンテキスト。全体像と他コンテキストとの関係は [../../../CONTEXT-MAP.md](../../../CONTEXT-MAP.md)。
本ファイルは用語集であり、実装詳細・仕様・決定の置き場ではない（設計判断は `CLAUDE.md` と `docs/ADR/`、契約は `wit/`）。

## 契約（`plecto:filter`）

**Filter**:
`plecto:filter` ワールドを実装した WASM コンポーネント。request/response を受けて decision を返す、
ホスト管理のチェーン内の一段。完全な HTTP ハンドラ（`wasi:http/middleware`）とは粒度が違う。
_Avoid_: plugin, middleware, extension（filter を指すとき）

**Decision**:
フィルタの型付き戻り値（WIT variant）。`continue`（次段へ）/ `modified`（書換えて継続）/
`short-circuit`（停止し即時応答を合成、upstream に到達させない）。
_Avoid_: result, verdict, response（ここでは別物を指す）

**Short-circuit**:
チェーンを打ち切りその場で応答を合成する decision。認証失敗・rate limit 超過がこれ。

**plecto:filter world**:
fast path（host）と untrusted な WASM フィルタの間の型付き境界。`wasi:http` の request/response
型を再利用しつつ、decision / hooks / host-API という Plecto 固有の語彙を持つ独自ワールド。

## 実行モデル

**init hook**:
フィルタごとに一度だけ走る高コスト初期化（regex compile・スキーマ構築・config ロード）の export。

**Per-request hook**:
リクエストごとに走るホット経路の export（`on-request` / `on-response`）。重い処理を混ぜないのが鉄則。

**Filter chain**:
fast path が順に駆動するフィルタの並び。request 側と response 側（逆順）で対称。

**Body disposition**:
フィルタを Header-only（ボディ非接触）と Body-transform（ボディ接触）に分ける契約レベルの分類。
この分類が、ボディ・ストリームをゼロコピーでバイパスしてよいフィルタとそうでないフィルタを決める。
_Avoid_: body mode（曖昧）, body flag（点ではなく分類）

**Header-only filter**:
ボディに触れないフィルタ。ボディ・ストリームはゼロコピーでバイパスできる。

**Body-transform filter**:
ボディを `stream<u8>` で流しながら読む/変換するフィルタ。WASM 税（コピー）を負う側。

**Trusted filter / Untrusted filter**:
信頼できる自家製フィルタ（再利用可能インスタンスのプールを init-once で再利用）と、第三者製で
per-request 新規生成＋ゼロ化を要するフィルタの区別。生成戦略と分離強度が変わり、ロード時の Isolation で
様式が決まる。

**Isolation（lifecycle mode）**:
ロード時に選ぶインスタンス生成・分離の様式。`Trusted`（再利用インスタンスのプールを checkout 方式で
再利用、init は instance ごと一度）/ `Untrusted`（リクエストごと新規生成、メモリは構造的に fresh）。
「誰が trusted か」の判定基準（署名・provenance）とは別レイヤで、こちらは**様式の選択**。
_Avoid_: trust level / trust score（点数ではなく lifecycle の様式）

**Instance pool**:
trusted フィルタの再利用可能インスタンスの固定容量プール。各リクエストはここから一つ checkout し、
実行後に返却する。飽和（全 checkout 済み）時は有界待ち後 fail-closed。一定数のリクエストを処理した
インスタンスは recycle（破棄・再生成）され、可変状態の持ち越しを bound する。
_Avoid_: instance cache（再利用の意図が出ない）, worker pool（スレッドプールと混同）

## 能力境界

**Host-API（capability）**:
ホストがフィルタに明示的に貸す能力（KV / counter / ratelimit / metrics / log / clock / random など）。
deny-by-default で、貸していないもの（任意 outbound・FS・socket）はサンドボックスが触れさせない。
能力ごとに別 interface に切る。
_Avoid_: syscall, runtime API（曖昧）

**host-counter（capability）**:
アトミックな名前付きカウンタを貸す能力。`increment(key, delta)` で加算して新値を返す
（wasi:keyvalue/atomics と同形）。ヒット数など*可変の業務状態*に使い、ホスト KV に載る。

**host-ratelimit（capability・token bucket）**:
トークンバケットのレート制限を貸す能力。リフィルとカウントは**ホストネイティブ**に保ち
（超ホット経路は WASM 境界を跨がない）、フィルタは「consult するか・どのキーで」を判断するだけ。
_Avoid_: throttle, quota（別概念）

**Outbound capability（outbound HTTP）**:
フィルタが外部へ HTTP を 1 本発行する能力（ext_authz / JWKS 取得 / token introspection / OPA 問い合わせ）。
標準形 `wasi:http/outgoing-handler` で貸し、他の host-API と同じ deny-by-default ゲート（`Linker`）を通す。
既定では**貸さない**。貸す瞬間に Outbound allowlist ＋ SSRF guard ＋ 資源境界で囲う（ADR 000036）。
_Avoid_: fetch, http-client（能力の貸与という含意が出ない）, egress（L4 の含意）

**Outbound allowlist**:
outbound を貸すフィルタごとに operator が宣言する送信先の許可リスト（scheme + host + port の exact match）。
operator 所有で**フィルタは上書きできない**（host-ratelimit のバケットと同じ「操作者が限度を持つ」モデル）。
deny-by-default——列挙外の送信先は拒否する。
_Avoid_: whitelist（用語）, filter allowlist（フィルタ自身が持つ含意）

**SSRF guard**:
outbound の送信先を**名前解決後のアドレス**で分類し、link-local（cloud-metadata 含む）/ loopback /
unspecified / multicast を allowlist と無関係に常時 deny する floor。private（RFC1918 / ULA）は per-filter の
opt-in（CIDR で絞る）でのみ許可。upstream connector とは独立した専用経路に内蔵する（ADR 000036 / 000027）。
_Avoid_: firewall, IP filter（汎用で境界の意図が出ない）

**IP-pinned connect**:
SSRF guard の要。ホスト自身が DNS 解決して全 A/AAAA を分類し、検査を通った**具体 IP に直接**接続する
（ホスト名で再接続しない）。検査と接続の間の DNS rebinding（TOCTOU）を塞ぐ。TLS の SNI/証明書検証は
元のホスト名で行う。
_Avoid_: IP allowlist（allowlist はホスト名側の別段）

## 可観測性（observability）

**Filter span**:
フィルタ 1 実行に対応する span。host が計時し、outcome（continue / modified / short-circuit / trap / deadline …）と
フィルタの host-log 行（span event）を載せて起こす。OTel データモデル上の span。
_Avoid_: trace（trace は span の集合で別粒度）, log line（点ではなく実行の span）

**Request span / Trace context**:
1 リクエスト transaction の親 span と、それを束ねる trace 文脈（trace-id + 親 span-id）。host が管理し、各 filter span の
親になる。フィルタは自分の trace 文脈を持たず、host が境界を跨いで伝播する（W3C `traceparent` で in/out）。`ConfigSnapshot`
が保持し、request 半と response 半で同一。
_Avoid_: session（別概念）, correlation id（trace context はより構造的）

**Telemetry sink**:
host が filter span を出す先（sync・deny-by-default で既定は no-op）。OTLP/SDK へのネットワーク export はこの継ぎ目越しの
named-deferred。`NoopSink` / `InMemorySink` / `MetricsSink` / `FanOutSink`。
_Avoid_: exporter（OTel SDK の async `SpanExporter` を指す。Plecto の sink は sync の別物）, collector（外部の集約先）

**Host-aggregated metrics**:
span ストリームから host が in-process 集約する RED 系メトリクス（実行数・エラー・short-circuit・レイテンシ）。フィルタ向け
metrics API は持たず、host が outcome と timing を知る立場で集約する。
_Avoid_: filter metrics（フィルタが emit する含意。現段階は host 観測のみ）

**wasi-otel（二段構え）**:
可観測性の将来の*ゲスト契約*（WASI、OpenTelemetry API に密結合）。現段階は host 側集約が主で、wasi-otel ゲスト契約は
成熟待ちの後段（named-deferred）。
_Avoid_: WASI Observe（より汎用な別 proposal）, OTel SDK（ホスト側実装の一手段）
