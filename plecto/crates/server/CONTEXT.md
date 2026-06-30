# Fast path — 用語集

接続を受け、TLS を終端し、HTTP を解し、リクエストを route 照合して filter chain を駆動し、upstream へ
転送する native-Rust 側の構成要素（`plecto-server`、ADR 000013）。全体像と他コンテキストとの関係は
[../../../CONTEXT-MAP.md](../../../CONTEXT-MAP.md)。本ファイルは用語集であり、実装詳細・仕様・決定の置き場では
ない（設計判断は `CLAUDE.md` と `docs/ADR/`、契約は `wit/`）。

## ルーティング

**Route**:
1 本の routing 規則。**match 基準**（match dimension の AND）に当たったリクエストを、その route の inline chain で
処理し、その転送先（単一 upstream または weighted backends）へ転送する。fast path はリクエストごとに route を
1 本だけ選ぶ。chain / strip_prefix / rate limit は route 単位で、転送先が weighted でも全 backend に共通に掛かる。
_Avoid_: rule（曖昧）, mapping（方向が出ない）

**Match dimension（照合軸）**:
route が当たるか否かを決める request 属性の一軸。host・path prefix・HTTP method・header（exact）・query
parameter（exact）。指定された軸はすべて満たす必要がある（AND）。host は case/port 非依存、header 名は
case-insensitive・値は byte-exact、query 名は case-sensitive・値は exact。指定のない軸は任意（wildcard）。
_Avoid_: matcher（機構名）, condition（曖昧）, predicate（実装語）

**Route selection（specificity 順）**:
当たった route が複数あるとき、より specific な 1 本を決定的に選ぶ照合。優先順は host 指定 > 最長 path prefix >
method 指定あり > header 一致数 > query 一致数、最後の同点は manifest 出現順で割る。一致なしは 404。
_Avoid_: dispatch（chain 駆動と紛らわしい）, 最長一致（path だけでなく多軸の specificity になった）

**Upstream**:
fast path が一致リクエストを転送する名前付きバックエンド。1 つ以上の **upstream instance** から成り、fast path
は転送時に healthy な instance を round-robin で 1 つ選ぶ（ADR 000017）。route は upstream を名前で指す。plain
HTTP/1.1 で転送する（upstream TLS は後続）。
_Avoid_: backend pool（pool ではなく instance 群で表す）, origin（CDN 文脈の語）

**Weighted backends（traffic split / canary）**:
1 本の route が単一 upstream の代わりに持てる、`{upstream, weight}` の重み付き集合。fast path は route 一致後に
weight 比でどの upstream group へ送るかを選び（その group 内の instance 選択は通常の round-robin LB）、新旧版を
同一 match 条件で重み付きに同時へ流す canary の正準プリミティブになる。`weight 0` は drain（流さない）。単一
upstream は 1 要素の weighted backends と等価（shorthand）。
_Avoid_: 重み付き LB（instance 間 LB と紛らわしい。ここは group 選択の一段上）, A/B（意味が狭い）

**Weighted apportionment split（決定的分配）**:
weighted backends から group を選ぶ決定的な分配。配分法（apportionment / error-diffusion の最大剰余規則）で
weight 比を満たしつつ各 group を均等にインタリーブし（バーストを作らない）、eligible instance を持たない
group は分配集合から外して残りで再正規化する（renormalize over healthy）。全 group が ineligible なら 503
（fail-closed）。round-robin LB の group 選択版にあたる。
_Avoid_: weighted random（非決定・バースト有りの別方式）, smooth weighted round-robin（同義だが特定プロキシ実装名）,
hash split（consistent hashing は別軸）

**Prefix strip（host-native rewrite）**:
route が宣言する path 書き換え。fast path が**転送直前**に適用し、chain は元 path を見たまま upstream は
書き換え後を受ける。フィルタ駆動の path 書き換え（WIT `set-path`）とは別物で、契約変更を要さない。
_Avoid_: filter rewrite（フィルタ駆動の書換は別レイヤ・後続）

## ロードバランシング / health（ADR 000017 / 000035）

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

**LB algorithm（per-upstream 選択則）**:
upstream ごとに選ぶ instance 選択則（ADR 000035）。`round_robin`（既定）・`least_request`（P2C）・`maglev`
（consistent hashing）の三択。route→group の weighted split（**Weighted apportionment split**）とは**別層**で、
これは選ばれた group の中でどの instance に流すかを決める。
_Avoid_: balancing strategy（曖昧）, scheduler（async ランタイム側と紛らわしい）

**Round-robin LB**:
healthy な upstream instance 集合を巡回選択する既定の分配（LB algorithm の `round_robin`）。eject された instance
は集合から外れ、復帰（restore）で戻る。
_Avoid_: balancing pool（曖昧）

**Least-request LB（P2C）**:
eligible な instance 集合から 2 つを一様乱択し、**active-request count** の少ない方（per-instance weight で
正規化した `(active+1)/weight` の小さい方）へ流す選択則（ADR 000035）。全走査せず O(1) 近傍で「ほぼ最小」を選ぶ
power-of-two-choices。不均一コスト / long-lived なリクエストで round-robin より in-flight を均す。
_Avoid_: least-connection（数えるのは TCP 接続ではなく in-flight な HTTP リクエスト）, least-loaded（全走査を含意）

**Active-request count（per-instance 選択信号）**:
ある instance へ現在 forward 中（in-flight）の HTTP リクエスト数。least-request LB が読む per-instance の信号で、
forward 開始で increment・応答到達 / 失敗で decrement する。circuit breaker（ADR 000028）の **per-group** in-flight
（飽和保護の cap）とは別フィールド・別関心事——同じ「active 数」を別粒度で読む。
_Avoid_: connection count（接続ではなくリクエスト）, load（曖昧）, in-flight cap（circuit breaker 側の語）

**Consistent hashing LB（maglev / affinity）**:
request の **hash key** を安定した instance へ写して同一キーを同一 instance へ固定する選択則（ADR 000035）。
session affinity / backend キャッシュの locality 向け。Plecto は v1 で **maglev**（素数 M の lookup table、
near-perfect な均一性 ＋ O(1) lookup）を採り、table は instance 集合上で固定して health flip では作り直さない。
primary が ineligible / key 欠落のときは round-robin へ fallback する。
_Avoid_: sticky session（成果であって機構名でない）, ring hash / ketama（別の consistent-hashing 変種。v1 は不採用）,
session pinning（曖昧）

**Hash key（affinity の投影）**:
consistent hashing LB が同一 instance へ固定する根拠にする request 属性——`header` の値か **source-IP**（peer socket
address の octets。spoofable な forwarding header は使わない）。untrusted（クライアントが付けられる）なので affinity
は性能最適化であって権限境界ではない。欠落時は round-robin へ fallback。
_Avoid_: routing key（route 照合は match dimension で別軸）, session id（用途が狭い）

**Per-instance weight**:
upstream instance に付ける整数 weight（既定 1）。least-request の比較と maglev の table 配分の双方を heterogeneous
（容量差のある）instance 向けに偏らせる。route→group split の **backend weight**（ADR 000034、どの group へ何 % か）
とは**別層の別 weight**——こちらは group 内でどの instance を選ぶかを偏らせる。
_Avoid_: backend weight（route→group split の重み。層が違う）, capacity（実装語）

**No-healthy fail-closed**:
ある upstream の全 instance が unhealthy のとき、upstream に流さず 503 を返す挙動。fail-closed テネットの upstream
版（404 no-route / 502 upstream-error とは別の fault）。
_Avoid_: circuit break（別概念）

**Retryable failure**:
別 instance への再送が許される転送失敗——応答ヘッダ到達前の **timeout**（ADR 000019）と、**接続失敗**（upstream が
未受信）。mid-response の transport fault や upstream の 5xx は retryable ではない（health 信号にもしない）。
_Avoid_: error（広すぎる）, 5xx（upstream 応答は retry 対象外）

**Upstream retry（bounded）**:
retryable failure を**別の**healthy instance へ最大回数まで再送する補完（ADR 000023）。timeout retry は冪等メソッド
限定（upstream が処理済みかもしれない）、接続失敗は任意メソッド（未受信なので安全）、いずれも **bodyless 限定**
（opaque body は再生不可）。別 instance が無ければ retry せず元の fault を返す。タイムアウトは health 信号にしない。
_Avoid_: failover（含意が広い）, hedging（並行投機ではなく逐次再送）

**Native rate limit（fast-path floor）**:
fast path が chain の**前**で consult する route 単位（または client-IP 単位）の素朴な token-bucket 上限（ADR
000033）。filterless route にも掛かる粗粒度の「床」で、超過は **429**（`rate-limited`）で fast-fail する。
host-native に完結し WASM 境界を跨がない。client-IP キーは peer アドレス（v4 /32・v6 /64）を**固定サイズ表**に
ハッシュして数え、無制限キーによる OOM（CWE-770）を構造的に塞ぐ。
_Avoid_: host-ratelimit（フィルタに**貸す**policy 形状の細粒度 capability、ADR 000026。native の床とは別機構）,
circuit break（upstream 飽和を 503 で守る別軸、ADR 000028）

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
