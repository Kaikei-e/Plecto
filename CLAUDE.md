# CLAUDE.md — Plecto

このファイルは Claude Code 用のプロジェクト規約であり、設計の要約と source of truth。設計判断の根拠
（Tenets / Fork 1–10 / stack / 未解決の問い）の詳細はリポジトリ内の founding design document（現在ドラフト段階）に
あるが、本ファイルが単体で完結するよう要点を内包する。確定後にこの行からリンクする。

## Plecto とは

セルフホスト可能・プログラマブルな **L7 リバースプロキシ / API ゲートウェイ（Rust）**。
**相補関係にある二つの構成要素**を WIT 型契約で結ぶ:

- **fast path（native Rust）** — 接続受付・TLS 終端・HTTP/1.1/2/3・ルーティング・LB・upstream 管理。
- **extension plane（WASM Component Model フィルタ）** — 各リクエストの判断（認証・書換・rate limit・WAF・
  ポリシー）。任意言語で書き、`plecto:filter` WIT 契約で差し込み、無停止で差し替える。

M0（`plecto:filter` 契約 + wasmtime ホスト）・M1（filter-runtime 堅牢化 + trusted インスタンスプール）・
M2 slice 1–2（HTTP/1.1 fast path + routing + rustls TLS 終端）が着地済み。動かせるデモは
`cargo run -p plecto-server --example demo`（旧 wasm-bindgen PoC は撤去）。設計が向かう先は
**wasmtime 埋め込みホスト + Component Model フィルタ**で、作業はこの方向を主軸に置く。

## リポジトリ構成

```
/ (git root = GitHub: Kaikei-e/Plecto)
├── (founding design doc)      ← 設計の源泉（ドラフト・確定後に命名）
├── CLAUDE.md                  ← このファイル
├── CONTEXT-MAP.md             ← ドメイン用語集の地図（コンテキスト分割・全体横断語彙）
├── docs/ADR/                  ← Architecture Decision Records（NNNNNN.md, 6桁）
└── plecto/                    ← Rust workspace（fast path / host / control / filter ランタイム）
    ├── wit/                   ← plecto:filter ワールド（契約・contract-first）
    ├── deny.toml              ← cargo-deny サプライチェーン方針（CI ブロッキング）
    └── crates/
        ├── host/              ← wasmtime 埋め込みホスト（plecto-host）。CONTEXT.md = Extension plane
        ├── control/           ← control plane（plecto-control）。CONTEXT.md = Control
        ├── server/            ← fast path（plecto-server）。tokio/hyper listener。CONTEXT.md = Fast path
        │                        （`examples/demo.rs` = 動かせるデモ）
        └── filter-hello/      ← 例フィルタ（wasm32-unknown-unknown ゲスト, workspace 外）
```

## コア原則（迷ったらこの順で優先）

**安全 × ポータビリティ × セルフホスト性 × 運用の単純さ** ＞ 機能網羅性 × 強い権限 × 分散デフォルト。

- **deny-by-default capability** — フィルタはホストが明示的に貸した能力以外、何も触れない（sandbox 強制）。
- **判断は型で** — フィルタの戻り値は `decision` variant（`continue` / `modified` / `short-circuit`）。
- **init と per-request を分離** — 高コスト初期化は init フックへ、ホット経路は軽く保つ。
- **フィルタはステートレス** — 状態はホスト KV（redb）に置く。
- **fail-closed** — フィルタ trap / deadline 超過で素通り（fail-open）させない。
- **single-node first** — 分散（foca/openraft）はオプトイン。
- **データプレーンで panic 禁止** — untrusted 入力で worker を巻き込まない。

## 開発コマンド

```bash
# Rust（plecto/ で実行）
cargo test --all
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
# WASM フィルタ
# 現行（無 WASI / header-only, ADR 000010）: wasm32-unknown-unknown でビルドし wit-component で component 化
cargo build --target wasm32-unknown-unknown --release   # crates/host/build.rs が ComponentEncoder で component 化
# 将来（body / stream<u8> / wasi:http 再利用, wasmtime 46 以降）: wasm32-wasip2 へ移行
cargo build --target wasm32-wasip2 --release      # Rust filter（→ componentize）
npx jco componentize <entry>.js --wit <world>.wit -o <out>.wasm   # JS filter
```

## 規約

- **ADR**: `docs/ADR/NNNNNN.md`（6桁ゼロ埋め）。frontmatter + wikilink `[[000NNN]]`。テンプレは
  `docs/ADR/template.md`。書くときは `plecto-adr-writer` スキル。
- **記述言語**: ドキュメント散文は日本語、コード/コマンド/ライブラリ名/WIT/識別子は英語（バイリンガル）。
- **TDD**: outside-in（E2E → WIT-conformance → Unit）。`tdd-workflow` スキル参照。最後に Phase 5
  （fmt/clippy/type/test のローカル CI パリティ）を必ず回す。
- **コミット**: RED と GREEN は別コミット。commit/push はユーザ確認を取る。

## スキル（`.claude/skills/`）

- 言語: `bp-rust`, `bp-typescript`
- アーキ/設計: `plecto-architecture`, `wit-contract-design`, `wasmtime-host`, `design-an-interface`,
  `improve-codebase-architecture`
- プロセス: `tdd-workflow`, `security-auditor`, `grill-me`, `grill-with-docs`, `qa`, `web-researcher`
- ドキュメント: `plecto-adr-writer`, `plecto-postmortem-writer`

> 設計判断は常にプロジェクトの設計 tenets（上記コア原則 / Fork 1–10）に従属する。矛盾する変更を
> 提案するときは、どの Fork を更新するかを明示し、必要なら ADR を書く。
