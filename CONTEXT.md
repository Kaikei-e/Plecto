# Plecto — ドメイン用語集

Plecto は、**相補関係にある二つの構成要素**（native-Rust の fast path / WASM の extension plane）を
WIT 型契約で結ぶ、セルフホスト可能な L7 リバースプロキシ / API ゲートウェイ。本ファイルは用語集
（glossary）であり、実装詳細・仕様・決定の置き場ではない。設計判断は `CLAUDE.md` と
`docs/ADR/`、契約は `wit/` を参照。

## アーキテクチャ全体

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

**Header-only filter**:
ボディに触れないフィルタ。ボディ・ストリームはゼロコピーでバイパスできる。

**Body-transform filter**:
ボディを `stream<u8>` で流しながら読む/変換するフィルタ。WASM 税（コピー）を負う側。

**Trusted filter / Untrusted filter**:
信頼できる自家製フィルタ（worker ごと事前生成＋pooling 再利用）と、第三者製で per-request 新規
生成＋ゼロ化を要するフィルタの区別。生成戦略と分離強度が変わる。

## 能力境界

**Host-API（capability）**:
ホストがフィルタに明示的に貸す能力（KV / counter / metrics / log / clock / random など）。
deny-by-default で、貸していないもの（任意 outbound・FS・socket）はサンドボックスが触れさせない。
能力ごとに別 interface に切る。
_Avoid_: syscall, runtime API（曖昧）
