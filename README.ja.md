<div align="center">

# Plecto

**セルフホスト可能・プログラマブルな L7 リバースプロキシ / API ゲートウェイ — Rust 製、WebAssembly で拡張する。**

[![CI](https://github.com/Kaikei-e/Plecto/actions/workflows/ci.yml/badge.svg)](https://github.com/Kaikei-e/Plecto/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust edition 2024](https://img.shields.io/badge/rust-edition%202024-orange.svg)](https://doc.rust-lang.org/edition-guide/)
[![Status: early development](https://img.shields.io/badge/status-early%20development-yellow.svg)](#ロードマップ)

[English](README.md) · 日本語

</div>

---

Plecto は、**相補関係にある二つの構成要素**を型付き [WIT](https://component-model.bytecodealliance.org/) 契約で**結ぶ**:

- **fast path**（native Rust） — 接続受付・TLS 終端・HTTP/1.1・2・3・ルーティング・ロードバランシング・upstream 管理。
- **extension plane**（WebAssembly Component Model フィルタ） — 各リクエストの*判断*（認証・ヘッダ/ボディ書換・rate limit・WAF・ポリシー）。**任意の言語**で書き、`plecto:filter` 契約で差し込み、**無停止で差し替え**る。

速さが価値になる経路は native Rust のまま。あなたのリクエスト・ロジックはサンドボックス化された WASM コンポーネントとして走り、**ホストが明示的に貸した能力以外、何も触れない** — 規約ではなくサンドボックスがそれを強制する。

> [!WARNING]
> **現状: 初期開発段階。** 設計は確定済み（11 本の ADR）で、最初の縦スライス — `plecto:filter` 契約・フィルタをロードして実行する wasmtime ホスト・例フィルタ・テスト一式 — は green で CI に載っている。**データ経路（TLS/HTTP/ルーティング/upstream）はまだ未実装で、現時点で実トラフィックをプロキシできない。** 今は「読める・テストを回せる・フィルタを書ける基盤」である。[ロードマップ](#ロードマップ)参照。

## なぜ Plecto か

ゲートウェイは必ず「**カスタムロジックをどこに置くか**」にぶつかる。従来の答えにはそれぞれトレードオフがある:

| アプローチ | プロセス内の速さ | サンドボックス | 言語自由 | 無停止差替 |
| --- | :---: | :---: | :---: | :---: |
| 設定 / DSL | ✅ | ✅ | ❌ | ✅ |
| 本体に再コンパイル組込 | ✅ | ❌ | ❌ | ❌ |
| 別プロセス（`ext_proc`・サイドカー） | ❌ | ✅ | ✅ | ✅ |
| **WASM フィルタ — Plecto** | ✅ | ✅ | ✅ | ✅ |

データプレーンのフィルタを WASM で動かすという発想は、**Envoy と proxy-wasm が切り拓き、約 10 年かけて実証**してきたものだ ―― その中核的な洞察に Plecto は多くを負っている。proxy-wasm は初期の WASM ABI（v0.2.1）を対象としており、その後 **Component Model と WIT** が型付き・多言語・合成可能な基盤として成熟した。Plecto は、それらの上にゲートウェイを素から築くとどうなるかを探る試みである。**Cloudflare の Pingora** をはじめとする高性能 Rust プロキシもまた、native なデータ経路がどれほど速くなり得るかを示してくれた。Plecto が特に焦点を当てるのは、**その native の速さと Component Model の extension plane を組み合わせる**こと ―― 自分で運用し、トラフィックも秘密も自分のインフラに留めたいチームのために、**データ主権**を第一原理として据える。

根拠と却下した代替案は [ADR 000001](docs/ADR/000001.md) を参照。

## 設計テネット

> 安全 × ポータビリティ × セルフホスト性 × 運用の単純さ **＞** 機能網羅性 × 強い権限 × 分散デフォルト。

- **deny-by-default capability** — フィルタはホストが貸した host-API（KV・counter・metrics・log・clock・random）以外に到達できない。任意の outbound・FS・socket は貸与されない限り不可。Component Model サンドボックスが強制する。
- **判断は型で** — フィルタは `decision` variant を返す: `continue` / `modified` / `short-circuit`。曖昧なフラグや暗黙の副作用にしない。
- **init と per-request を分離** — 高コスト初期化（regex compile・スキーマ構築）は `init` フックへ、per-request のホット経路は軽く保つ。
- **フィルタはステートレス** — rate limit・セッション・キャッシュ等の状態はホスト KV に置く。だからフィルタはプール再利用・スケール・無停止差替が綺麗に決まる。
- **fail-closed** — フィルタの trap や deadline 超過で素通り（fail-open）させない。
- **single-node first** — 一台で仕事は完結する。分散（メンバーシップ・設定合意）はオプトイン。
- **データプレーンで panic 禁止** — たった一つの不正リクエストが worker を巻き込んではならない。

## アーキテクチャ

```
            ┌────────────────────────── fast path (native Rust) ──────────────────────────┐
client ───▶ │ accept · TLS · HTTP/1.1·2·3 · routing · LB · upstream conn mgmt · hot-reload │ ───▶ upstream
            └───────────────┬───────────────────────────────────────────────┬─────────────┘
                            │  request chain                    response chain │
                            ▼  (WIT: plecto:filter)             (reverse)       ▲
            ┌──────────── extension plane (WASM Component Model filters) ───────────────┐
            │  各フィルタ: init フック（重い・一度） + per-request フック（ホット）       │
            │  decision を返す: continue | modified | short-circuit                     │
            │  貸与された host-API だけに触れる（deny-by-default capability）            │
            └───────────────────────────────────────────────────────────────────────────┘
                                         │ host-API (KV / counter / metrics / log / clock / random)
                                         ▼
                              host-held state: redb (KV / rate-limit / cache)
```

**判断の指針:** ユーザー固有のロジック・ポリシー・WAF・認証・書換 → WASM フィルタ。TLS・ルーティング・LB・コネクションプール・グローバルカウンタ → native Rust。WASM 税（データコピー＋ホストコール）はリクエスト判断ロジックにのみ課し、速い経路には課さない。

## フィルタ契約

Plecto の中核は `plecto:filter` WIT ワールド — Plecto 固有の語彙（型付き `decision`、init/per-request フック、deny-by-default な host-API）を持ちつつ、polyglot 互換のため標準型を再利用する独自ワールドである。

```wit
package plecto:filter@0.1.0;

interface types {
  // request 側フィルタの型付き戻り値。決して裸のフラグにしない。
  variant request-decision {
    %continue,                       // 次のフィルタへそのまま渡す
    modified(request-edit),          // edit を適用して継続
    short-circuit(http-response),    // チェーンを止め、ここで応答を合成する
  }
}

// deny-by-default: 能力ごとに 1 interface。フィルタは貸与されたものだけを import する。
interface host-kv      { get: func(key: string) -> option<list<u8>>; set: func(key: string, value: list<u8>); /* … */ }
interface host-counter { increment: func(key: string, delta: s64) -> s64; /* アトミックな名前付き counter */ }
interface host-log     { log: func(level: level, message: string); }
// host-ratelimit は token bucket をホストネイティブに保つ —— ホット経路の refill/カウントは WASM 境界を
// 跨がず、フィルタは「consult するか・どのキーで」を判断するだけ（ADR 000005）。

world filter {
  // 貸与された能力のみ —— log · clock · kv · counter · rate-limit
  import host-log;  import host-clock;  import host-kv;  import host-counter;  import host-ratelimit;
  export init: func();                                       // 重い・instance ごと一度
  export on-request:  func(req: http-request)  -> request-decision;   // ホット経路
  export on-response: func(resp: http-response) -> response-decision;  // ホット経路
}
```

> v0.1.0 は安定版 wasmtime 45 toolchain 上で意図的に **sync・header-only**。`stream<u8>` ボディ・async フック・`wasi:http` 型再利用は wasmtime 46 で導入する — [ADR 000003](docs/ADR/000003.md) / [ADR 000010](docs/ADR/000010.md) 参照。

## フィルタを書く

フィルタはワールドを実装したコンポーネントにすぎない。同梱の例（`crates/filter-hello`、Rust）:

```rust
wit_bindgen::generate!({ path: "../../wit", world: "filter" });

struct FilterHello;

impl Guest for FilterHello {
    fn init() {}

    fn on_request(req: HttpRequest) -> RequestDecision {
        host_log::log(host_log::Level::Info, "filter-hello: on-request");
        if req.headers.iter().any(|h| h.name.eq_ignore_ascii_case("x-plecto-block")) {
            RequestDecision::ShortCircuit(HttpResponse { status: 403, /* … */ })
        } else {
            RequestDecision::Continue
        }
    }

    fn on_response(_: HttpResponse) -> ResponseDecision { ResponseDecision::Continue }
}

export!(FilterHello);
```

契約が WIT なので、**WASM コンポーネントへコンパイルできる言語ならどれでもフィルタを書ける** — Rust・Go（TinyGo）・JavaScript/TypeScript（`jco`）・Python（`componentize-py`）。polyglot フィルタ SDK は[ロードマップ](#ロードマップ)に載っている。

## 試す

```bash
# 前提: Rust 1.96+（edition 2024）と wasm32-unknown-unknown ターゲット。
rustup target add wasm32-unknown-unknown

# 全ビルド + テスト。host の build script が例フィルタを WASM コンポーネントへ
# コンパイルし、テストがそれを wasmtime ホストにロードして契約を検証する。
cd plecto
cargo test --all
```

テストはスライスを end-to-end で実証する: リクエストがホストを通って実フィルタ・コンポーネントへ流れ、型付き `decision` が往復し、フィルタは**貸与された能力だけ**に到達する（例コンポーネントは `plecto:filter/*` のみを import し、WASI・network・filesystem には一切アクセスしない）。

### デモプロキシを動かす

自己完結の example が**本番パス**を一通り組み上げる —— 例フィルタに署名し、オフライン OCI レイアウトに梱包し、TLS 証明書を生成し、manifest を書き、fast path を HTTPS で serve —— して、試すコマンドを表示する:

```bash
cd plecto
cargo run -p plecto-server --example demo   # https://localhost:8443 で serve、Ctrl-C で停止

# 別シェルで（自己署名なので curl -k）:
curl -k https://localhost:8443/api/hello                         # routing + /api strip + 転送
curl -k -H 'x-plecto-block: 1' https://localhost:8443/api/hello  # フィルタが 403 で short-circuit
for i in 1 2 3; do curl -k -s -o /dev/null -w '%{http_code} ' \
  -H 'x-plecto-ratelimit: 1' https://localhost:8443/api/hello; done   # 200 200 429（host-native rate limit）
curl -k https://localhost:8443/nope                             # ルート無し → 404
```

cosign 風の署名 ＋ SBOM 検証、TLS 終端（rustls）、host＋path-prefix routing と host-native prefix strip、フィルタチェーン（continue / modify / short-circuit / rate-limit）、response 側書換 —— を実 HTTPS で一気に通す。

## ロードマップ

Plecto は ADR ファーストで作る。各マイルストーンは `docs/ADR/` の特定の設計判断を具体化する。

- **M0 — 基盤** ✅ *(完了)*
  `plecto:filter@0.1.0` 契約、フィルタをロード&実行する wasmtime ホスト、deny-by-default の能力境界（log / clock / kv）、例フィルタ、E2E/conformance/unit テスト、CI。— [ADR 1](docs/ADR/000001.md) · [2](docs/ADR/000002.md) · [10](docs/ADR/000010.md)
- **M1 — フィルタ runtime の堅牢化** ✅ *(着地)*
  trust 分岐ランタイム —— `InstancePre`、trusted は固定容量・遅延充填の**インスタンスプール**をリクエストごとに checkout 再利用（pooling エンジンが初めて活きる。飽和は有界待ち後 fail-closed、決定的に trap するフィルタには pool 全体の circuit breaker が開き、一定リクエスト数で instance を recycle して状態蓄積を bound）、untrusted = on-demand エンジンで per-request fresh（線形メモリは構造的に fresh ゆえゼロ化不要）、redb-backed host KV + アトミック counter + **ホストネイティブな token-bucket rate limit**、全 host-API キーをフィルタごとに名前空間化、ephemeral なホット経路は毎コミット fsync を省く、**epoch 計量 + メモリ/テーブル上限**を実装。trusted/untrusted の分岐は perf でなく init/zeroization の矛盾ゆえの**必然**。**M2 へ繰延**（fast-path server と不可分）: プールを tokio/quinn データ経路へ結線する sync↔async ブリッジと、状態 backend の sharding。— [ADR 4](docs/ADR/000004.md) · [5](docs/ADR/000005.md) · [6](docs/ADR/000006.md) · [11](docs/ADR/000011.md) · [12](docs/ADR/000012.md)
- **M2 — データ経路（fast path）** 🚧 *(slice 1–2 着地)*
  **着地（slice 1）:** `plecto-server` crate —— tokio + hyper の **HTTP/1.1** listener。各リクエストを host＋path-prefix で route 照合し、その route の filter chain を `spawn_blocking` ブリッジ経由で M1 の trusted プールに載せて駆動（wasmtime の `!Send` Store は `.await` を跨がない）、host-native な prefix strip を適用し、route の upstream（hyper-util pooling client）へ転送、ボディは opaque にストリーム透過。*Plecto はこれで実際のリバースプロキシになった。* **着地（slice 2 — TLS）:** rustls（ring）の **TLS 終端**。証明書は manifest（`[[tls]]`、SNI 選択＋host-less default）で宣言し、control プレーンで構築するので bad cert は load 時 **fail-closed**・reload は証明書をアトミックに差し替え。ALPN は `http/1.1` を広告。*Plecto は HTTPS を終端する。* **保留（後続スライス）:** HTTP/2（h2 over ALPN）→ HTTP/3（quinn）、インスタンス間ロードバランシング & upstream health。— [ADR 12](docs/ADR/000012.md) · [13](docs/ADR/000013.md) · [14](docs/ADR/000014.md)
- **M3 — async & ボディ** *(2段トリガ)*
  **Stage 1 — host が P3 を走らせられる:** wasmtime 46（Component Model async + WASI 0.3 を default 有効）へ更新。**Stage 2 — P3 ゲストを実用 DX で書ける:** `wasm32-wasip3` の Tier 2 化 / wit-bindgen async の成熟。ボディ作業（非同期ファースト契約・`stream<u8>` ボディ・`wasi:http` 型再利用・body-transform フィルタ）は **Stage 2** に紐づける（46 到来直後に始めると guest toolchain で詰まりうる）。body 非接触は**型レベル**（header/body を別 export）で表し、ゼロコピー bypass を契約から導く。stream splicing 自体は WASI 0.3.x で後続。— [ADR 3](docs/ADR/000003.md) · [5](docs/ADR/000005.md) · [10](docs/ADR/000010.md)
- **M4 — provenance & 無停止リロード**
  OCI artifact によるフィルタ配布 + cosign 署名検証、宣言的マニフェストの content hash で整合する無停止リロード。— [ADR 6](docs/ADR/000006.md) · [8](docs/ADR/000008.md)
- **M5 — 可観測性 & オプトイン分散**
  `wasi-otel` トレーシング（span 文脈はホストが伝播）、オプトインの `foca`/`openraft` 設定合意。— [ADR 7](docs/ADR/000007.md) · [9](docs/ADR/000009.md)
- **M6 — polyglot SDK & リファレンスフィルタ**
  Go / JS / Python のフィルタテンプレート、リファレンスの auth / rate-limit / WAF フィルタ。

## リポジトリ構成

```
.
├── plecto/                    # Rust workspace（native 側）
│   ├── wit/world.wit          # plecto:filter 契約（contract-first）
│   ├── deny.toml              # cargo-deny サプライチェーン方針（CI ブロッキング）
│   └── crates/
│       ├── host/              # wasmtime 埋め込み: Linker, InstancePre, host-API（+ CONTEXT.md）
│       ├── control/           # control plane: manifest, OCI load, chain, reload, TLS（+ CONTEXT.md）
│       ├── server/            # fast path: tokio/hyper listener, routing, upstream（+ CONTEXT.md, examples/demo.rs）
│       └── filter-hello/      # 例フィルタ（wasm32-unknown-unknown ゲスト）
├── docs/ADR/                  # Architecture Decision Records（000001–000017）
├── CLAUDE.md                  # プロジェクト規約・設計要約
└── CONTEXT-MAP.md             # ドメイン用語集の地図（コンテキスト分割）
```

## 設計判断（ADR）

Plecto は load-bearing な判断をすべて ADR に、Fork 形式（*判断 / 根拠 / 再検討条件*）で記録する:

| # | 判断 |
| --- | --- |
| [001](docs/ADR/000001.md) | WASM Component Model / WIT を採用し、相補的な二つの構成要素で構成する |
| [002](docs/ADR/000002.md) | 独自 `plecto:filter` ワールドを定義し `wasi:http` 型を再利用する |
| [003](docs/ADR/000003.md) | 非同期ファースト契約: `stream<u8>` ボディ、`wasm32-wasip2` → P3 |
| [004](docs/ADR/000004.md) | フィルタはプール再利用・ステートレス、状態はホスト KV（redb）へ |
| [005](docs/ADR/000005.md) | header-only と body-transform を分離、ホット経路はネイティブに |
| [006](docs/ADR/000006.md) | セキュリティ: deny-by-default 能力・epoch 計量・OCI 署名・pooling ゼロ化 |
| [007](docs/ADR/000007.md) | 可観測性は `wasi-otel`、トレース span はホストが伝播 |
| [008](docs/ADR/000008.md) | OCI artifact で配布、content hash で整合する無停止リロード |
| [009](docs/ADR/000009.md) | 単一ノード・ファースト、分散はオプトイン、静的宣言的設定 + 無停止 reload |
| [010](docs/ADR/000010.md) | 初回増分は sync + 自前 http 型・`wasm32-unknown-unknown`、async は wasmtime 46 へ |
| [011](docs/ADR/000011.md) | 「ステートレス」=持ち越す可変状態を持たない、trusted/untrusted 分岐は init/zeroization の矛盾ゆえの必然 |

## コントリビュート

Plecto は outside-in TDD（E2E → WIT-conformance → unit）に従い、load-bearing な判断を ADR に記録する。規約は [CLAUDE.md](CLAUDE.md) 参照。PR 前のローカル CI パリティ:

```bash
cd plecto
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

## ライセンス

**Apache License, Version 2.0** — [LICENSE](LICENSE) を参照。Apache-2.0 の特許付与条項はインフラ・プロジェクトに適し、Envoy・Linkerd・containerd でも採用されている。

## 先行研究 & 謝辞

Plecto は [Envoy](https://www.envoyproxy.io/) / [proxy-wasm](https://github.com/proxy-wasm)、[Cloudflare Pingora](https://github.com/cloudflare/pingora)、[Bytecode Alliance](https://bytecodealliance.org/)（[wasmtime](https://wasmtime.dev/)、[WIT と Component Model](https://component-model.bytecodealliance.org/)）の肩の上に立っている。
