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
