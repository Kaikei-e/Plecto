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

速度が要となる経路は native Rust のまま。リクエストのロジックはサンドボックス化された WASM コンポーネントとして走り、**ホストが明示的に貸した能力以外には何も触れられない** —— それを強制するのは規約ではなくサンドボックスである。

> [!WARNING]
> **現状: 初期開発段階。** 設計は確定済み（24 本の ADR）で、基盤は end-to-end で動く: `plecto:filter` 契約・フィルタをロードして実行する wasmtime ホスト・そして **fast path** —— **HTTP/1.1・HTTP/2（ALPN）・HTTP/3（QUIC）** と **TLS** を終端し、host＋path-prefix で routing し、クライアント IP を edge モデルで伝播し、**healthy な upstream instance へロードバランシングする**（round-robin ＋ active/passive health・per-upstream timeout・request-level retry）。テスト一式は green で CI に載っている —— 読める・動かせる・フィルタを書ける基盤である。[ロードマップ](#ロードマップ)参照。

## なぜ Plecto か

ゲートウェイは必ず「**カスタムロジックをどこに置くか**」にぶつかる。従来の答えにはそれぞれトレードオフがある:

| アプローチ | プロセス内の速さ | サンドボックス | 言語自由 | 無停止差替 |
| --- | :---: | :---: | :---: | :---: |
| 設定 / DSL | ✅ | ✅ | ❌ | ✅ |
| 本体に再コンパイル組込 | ✅ | ❌ | ❌ | ❌ |
| 別プロセス（`ext_proc`・サイドカー） | ❌ | ✅ | ✅ | ✅ |
| **WASM フィルタ — Plecto** | ✅ | ✅ | ✅ | ✅ |

データプレーンのフィルタを WASM で動かすという発想は、**Envoy と proxy-wasm が切り拓き、約 10 年かけて実証**してきたものだ ―― その中核的な洞察に Plecto は多くを負っている。proxy-wasm は初期の WASM ABI（v0.2.1）を対象としており、その後 **Component Model と WIT** が型付き・多言語・合成可能な基盤として成熟した。Plecto は、それらの上にゲートウェイを一から築くとどうなるかを探る試みである。**Cloudflare の Pingora** をはじめとする高性能 Rust プロキシもまた、native なデータ経路がどれほど速くなり得るかを示してくれた。Plecto が特に焦点を当てるのは、**その native の速さと Component Model の extension plane を組み合わせる**こと ―― 自分で運用し、トラフィックも秘密も自分のインフラに留めたいチームのために、**データ主権**を第一原理として据える。

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

```mermaid
flowchart LR
    client(["クライアント"])
    upstream(["upstream"])

    subgraph fast["fast path — native Rust（速度が要）"]
        direction TB
        net["接続受付 · TLS 終端<br/>HTTP/1.1 · HTTP/2 · HTTP/3"]
        route["routing · load balancing<br/>upstream プール · hot-reload"]
        net --> route
    end

    subgraph ext["extension plane — WASM Component Model フィルタ（あなたのロジック）"]
        direction TB
        filter["各フィルタ: init（重い・一度） + on-request / on-response（ホット）<br/>型付き decision を返す — continue · modified · short-circuit<br/>deny-by-default: 貸与された host-API だけに触れる"]
    end

    state[("host 保持の状態<br/>redb — KV · rate-limit · cache")]

    client -->|リクエスト| fast
    fast -->|"転送 — prefix-strip · X-Forwarded · timeout · retry"| upstream
    fast <-->|"plecto:filter 契約（WIT） — request chain から response chain（逆順）"| ext
    ext -->|"host-API — KV · counter · rate-limit · log · clock"| state
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

> v0.1.0 は意図的に **sync・header-only**。ホスト側 async 移行（M3 Stage 1、[ADR 000021](docs/ADR/000021.md)）は **着地済み**: フックは `call_async` で wasmtime fiber 上に走り、`block_on` で sync API に橋渡しされる。`stream<u8>` ボディ・async フック・`wasi:http` 型再利用は P3 ゲスト toolchain が枯れてから Stage 2 で続く — [ADR 000003](docs/ADR/000003.md) / [ADR 000010](docs/ADR/000010.md) / [ADR 000020](docs/ADR/000020.md) 参照。

## フィルタを書く

フィルタはワールドを実装したコンポーネントにすぎない。同梱の例（`examples/filters/filter-hello`、Rust）:

```rust
wit_bindgen::generate!({ path: "../../../wit", world: "filter" });

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

### デモを動かす

ユースケース別の自己完結 example が `examples/<name>/` に 5 つある。どれも**本番ロードパス**（署名＋オフライン OCI レイアウト＋検証＋ロード、すべて fail-closed）を組み、小さな upstream を立て、実プロキシを serve し、起動時に貼り付け用の `curl` コマンドを表示する。実行:

```bash
cd plecto
cargo run -p plecto-server --example <name>   # Ctrl-C で停止
```

手早く全部見るなら `./examples/try.sh <name>`（または `all`）: example を起動し、readiness を待ち、`curl` を流し、結果を可視化して、後片付けまで自動でやる。

| `<name>` | 見せるもの |
| --- | --- |
| `wasm-auth` | **実用 WASM フィルタ** —— 署名済みの API キー認証コンポーネント（`examples/filters/filter-apikey`）。鍵が無ければ 401、認証できれば呼び出し元の identity を付与し、per-user のリクエスト数を host KV で数える。Plecto の核。 |
| `load-balancing` | 1 つの upstream を 3 instance に分散: healthy 集合の round-robin、active health probe、unhealthy 化での eject、全滅時の 503（ADR 000017）。 |
| `filter-chain` | plain HTTP で filter chain: continue / modify（ヘッダ書換）/ short-circuit 403 / host-native rate limit。 |
| `tls-http` | 同一ポートで TLS 終端＋HTTP/1.1・HTTP/2（ALPN）・HTTP/3（QUIC）、`Alt-Svc` による h3 広告。 |
| `hot-reload` | manifest を編集して `kill -HUP <pid>`、無停止で設定をアトミックに差し替え（壊れた編集は fail-closed）。 |

まず読むなら `wasm-auth`: 貸与された host-API だけに触れるサンドボックス・コンポーネントとしてカスタムなリクエスト処理が走る様子 —— cosign 風署名＋SBOM 検証・型付き `decision`・host 保持の状態 —— が端から端まで見える。

## ロードマップ

Plecto は ADR ファーストで作る。各マイルストーンは `docs/ADR/` の特定の設計判断を具体化する。

- **M0 — 基盤** ✅ *(完了)*
  `plecto:filter@0.1.0` 契約、フィルタをロード&実行する wasmtime ホスト、deny-by-default の能力境界（log / clock / kv）、例フィルタ、E2E/conformance/unit テスト、CI。— [ADR 1](docs/ADR/000001.md) · [2](docs/ADR/000002.md) · [10](docs/ADR/000010.md)
- **M1 — フィルタランタイムの堅牢化** ✅ *(着地)*
  trusted / untrusted で生成戦略を分ける。trusted は固定容量のプールをリクエストごとに借りて返し（飽和時は上限付きで待ってから fail-closed、trap が続けばプール全体のブレーカーが開き、一定回数で recycle）、untrusted は毎回新しく生成する（線形メモリが構造的にまっさらなのでゼロ化が要らない）。状態は redb 上の host KV とアトミックカウンタに置き、token-bucket のレート制限はホスト側で持つ。epoch 計量とメモリ/テーブル上限も実装済み。trusted/untrusted を分けるのは性能のための選択ではなく、init とゼロ化を両立できないことによる必然。
- **M2 — データ経路（fast path）** 🚧 *(slice 1–6 着地)*
  tokio + hyper + quinn で書いた `plecto-server`。**HTTP/1.1・HTTP/2（ALPN）・HTTP/3（QUIC）** と **TLS**（rustls、証明書は manifest 宣言、不正なら fail-closed）を終端し、host＋path-prefix で route を選び、その chain を `spawn_blocking` 経由で M1 のプールに載せて回す。upstream は **healthy な instance に round-robin で分散**し、active/passive の health check（pessimistic 起動、全滅すれば 503 で fail-closed）、クライアント IP の edge 伝播（`X-Forwarded-For` / `X-Real-IP` を実 peer から付け直す）、per-upstream の request timeout（504）、別 instance への有界リトライまで備える。*次:* upstream TLS と least-conn/EWMA。
- **M4 — provenance & 無停止リロード** ✅ *(着地)*
  OCI artifact によるフィルタ配布（オフライン image-layout・digest ピン）+ cosign 署名検証 + SBOM↔component バインド、宣言的マニフェストの content hash で整合する無停止リロード（`ArcSwap` 原子適用・all-or-nothing・SIGHUP 駆動）。残るのは*リモート*レジストリ取得経路（`wkg` 境界・設計上 out-of-band）。— [ADR 6](docs/ADR/000006.md) · [8](docs/ADR/000008.md)
- **M5 — 可観測性 & オプトイン分散** 🚧 *(span/metrics の中核は着地・export は deferred)*
  **着地:** ホスト伝播の W3C トレース文脈（受信 `traceparent` をプロキシ越しに継続）、フィルタ実行ごとの span（OpenTelemetry データモデル）、sync な `TelemetrySink`（in-memory + ホスト集計の RED メトリクス）。**deferred:** OTLP ネットワーク export（`wasi-otel` / SDK exporter — no-tokio 維持のため named-deferred）とオプトインの `foca`/`openraft` 設定合意。— [ADR 7](docs/ADR/000007.md) · [9](docs/ADR/000009.md)
- **M3 — async & ボディ** 🚧 *(Stage 1 着地・Stage 2 はゲート)*
  M4・M5 がほぼ片付いたので、ここが次の主戦場になる。**Stage 1（着地）:** [wasmtime 46](https://github.com/bytecodealliance/wasmtime/releases/tag/v46.0.0)（2026-06-22）が WASI 0.3 と Component Model async を既定で有効にした。host は guest のフックを `call_async` で wasmtime の fiber 上に走らせ、まだ sync の公開 API へ `block_on` で橋渡ししている。おかげで `spawn_blocking` の経路には手を付けずに済んでいる（conformance と unit は 46 で green）。**Stage 2（ゲート）:** `run_pooled` の fiber 化、server 側の `spawn_blocking` 撤去、production の `stream<u8>` ボディ契約は、P3 ゲストの toolchain（`wasm32-wasip3` の Tier-2 化、wit-bindgen async）が枯れるまで凍結する。方向は [ADR 20](docs/ADR/000020.md) で確定済み —— `plecto:filter` を `wasi:http` 型へ収斂させつつ、deny-by-default は型語彙と切り離して保つ。
- **M6 — polyglot SDK & リファレンスフィルタ**
  Go / JS / Python のフィルタテンプレート、リファレンスの auth / rate-limit / WAF フィルタ。

## リポジトリ構成

```
.
├── plecto/                    # Rust workspace（native 側）
│   ├── wit/world.wit          # plecto:filter 契約（contract-first）
│   ├── deny.toml              # cargo-deny サプライチェーン方針（CI ブロッキング）
│   ├── crates/
│   │   ├── host/              # wasmtime 埋め込み: Linker, InstancePre, host-API（+ CONTEXT.md）
│   │   ├── control/           # control plane: manifest, OCI load, chain, reload, TLS/QUIC（+ CONTEXT.md）
│   │   └── server/            # fast path: HTTP/1.1·2（hyper）+ HTTP/3（quinn）, routing, LB, upstream（+ CONTEXT.md）
│   └── examples/              # 動かせるデモ（<use-case>/）+ 例フィルタ guest（filters/）
│       ├── <use-case>/        # デモ 5 種: cargo run -p plecto-server --example <name>
│       └── filters/           # 例 plecto:filter guest（独立 workspace・build.rs が component 化）
│           ├── filter-hello/  # conformance 用の例フィルタ（wasm32-unknown-unknown ゲスト）
│           └── filter-apikey/ # 実用例フィルタ: API キー認証ゲート（WASM コンポーネント）
├── docs/ADR/                  # Architecture Decision Records（000001–000024）
├── CLAUDE.md                  # プロジェクト規約・設計要約
└── CONTEXT-MAP.md             # ドメイン用語集の地図（コンテキスト分割）
```

## 設計判断（ADR）

Plecto は重要な設計判断をすべて ADR に、Fork 形式（*判断 / 根拠 / 再検討条件*）で記録している。24 本すべては [`docs/ADR/`](docs/ADR/) にあり、起点は [ADR 000001](docs/ADR/000001.md)（相補的な二つの構成要素）。各 ADR は土台にした判断へ相互リンクしている。

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
