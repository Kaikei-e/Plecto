# Plecto — Context Map

Plecto は、**相補関係にある二つの構成要素**（native-Rust の fast path / WASM の extension plane）を
WIT 型契約で結ぶ、セルフホスト可能な L7 リバースプロキシ / API ゲートウェイ。用語集はコンテキストごとに分割し、
本ファイルはその地図——どのコンテキストがどこにあり、どう関係するか——と、全体に跨る語彙だけを持つ。実装詳細・
仕様・決定は置かない（設計判断は `CLAUDE.md` と `docs/ADR/`、契約は `wit/` を参照）。

## アーキテクチャ全体（cross-cutting）

**Fast path**:
接続受付・TLS 終端・HTTP/1.1/2/3・ルーティング・LB・upstream 管理を担う native-Rust 側の構成要素。
チェーンを駆動する側。
_Avoid_: core, engine（曖昧）, data plane（多義）

**Extension plane**:
各リクエストの判断（認証・書換・rate limit・WAF・ポリシー）を担う WASM フィルタの実行基盤。
fast path から WIT 契約越しに駆動される側。
_Avoid_: plugin layer, middleware layer

**Two halves（相補関係にある二つの構成要素）**:
fast path と extension plane の対。相補関係にあり、両者を WIT 型契約で結ぶ。
_Avoid_: 二つの半身（身体比喩で生硬・"two halves" の直訳調）, より合わせる糸（比喩過多）

## Contexts

- [Extension plane / host runtime](./plecto/crates/host/CONTEXT.md) — `plecto:filter` 契約・フィルタ実行モデル・
  能力境界（host-API）。wasmtime 埋め込みホスト（`plecto-host`）。
- [Control](./plecto/crates/control/CONTEXT.md) — 宣言的マニフェスト・無停止 reload・単一ノード／分散 opt-in・
  config version（`plecto-control`）。
- [Fast path](./plecto/crates/server/CONTEXT.md) — 接続／HTTP／routing／upstream 転送（`plecto-server`、ADR 000013）。
  M2 slice 1–5 着地（host＋path-prefix routing・host-native prefix strip・rustls TLS 終端 SNI 込み
  ADR 000014／TLS+ALPN 上の HTTP/2 終端 ADR 000015、h2c は不採用／quinn+h3 の独立 UDP listener で HTTP/3 終端・
  Alt-Svc 広告 ADR 000016、0-RTT 無効／複数 upstream instance を round-robin LB ＋ active/passive health check で
  分散・全 unhealthy は 503 fail-closed ADR 000017、LB algorithm を weighted least-request P2C ＋ weighted maglev
  consistent hashing へ拡張 ADR 000035）。upstream への h2/h3・EWMA/latency-based LB・ring hash・ノード横断 health
  は後続スライス。

## Relationships

- **Fast path → Extension plane**: fast path が各リクエストを `plecto:filter` 契約越しに filter chain へ駆動する。
- **Control → Extension plane**: マニフェストが filter を OCI digest で pin し、chain 順と trust root を宣言する。
  reload が filter set + chain をアトミックに差し替える。trust root は構築時固定で、reload では変えない。
- **Control → Fast path**: マニフェストが route（match 軸 host/path/method/headers/query → chain ＋ 転送先）を宣言し、
  Control が specificity 順の route 照合と route 毎の chain dispatch を提供する。転送先は単一 upstream または
  weighted backends（traffic split / canary）。Fast path は per-request に snapshot を取り、route を選んで chain を
  駆動する（ADR 000013 / 000034）。
