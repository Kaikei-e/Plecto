# Plecto ベンチマーク計画 / runbook

Plecto の二つの半身——**native fast path**（接続・TLS・HTTP・routing・LB・upstream）と
**extension plane**（WASM フィルタ＋ host-API）——の性能を、**method を公開しつつ raw 出力は出さない**方針で
測る。結果（数値・グラフ・考察）は [`../performance/README.md`](../performance/README.md) が source of truth。
本ファイルは「何を・なぜ・どう測るか」の runbook。

## 方針（tenets）

- **canonical runner は1本**: [`perf/run-perf.sh`](perf/run-perf.sh)。core-pin（`taskset`）で proxy と
  generator を**互いに素な CPU 集合**に固定し、generator が proxy の core を奪わないようにする。
  出力は `performance/data/*.csv` → [`../performance/plot.py`](../performance/plot.py) → `performance/img/*.webp`。
- **負荷はこのマシン内で完結**: generator → proxy → in-process upstream はすべて loopback。telemetry は無効
  （`K6_NO_USAGE_REPORT=true`、Influx/Grafana の phone-home off）。**負荷実行時に外部へ通信しない**。
  Docker image / generator binary の**取得（setup）は外部 OK**——禁じるのは「負荷をかける最中の外部通信」。
- **絶対値ではなく invariant を読む**: host / clock 依存の絶対 throughput ではなく、**比・曲線形・時定数・
  µs/req・enforcement の収束**を回帰の signal とする。loopback は kernel short-circuit で latency を過小評価する
  ため、数値は下界・回帰用として扱う（`performance/README.md` の caveat 参照）。
- **open-loop を tail の権威に**: closed-loop（`constant-vus`）は throughput 天井、open-loop
  （`constant-arrival-rate`）は coordinated-omission-safe な tail。両者を併記し、tail は open-loop を採る。

## ツール

| 用途 | ツール | 備考 |
| --- | --- | --- |
| closed/open-loop・rate-limit・body | [k6](https://grafana.com/docs/k6/latest/) | PATH の k6 を使用（download しない） |
| single-route overhead・TLS・churn | [oha](https://github.com/hatoo/oha) | `~/.cargo/bin/oha`、軽い generator で proxy 天井を出す |
| round-robin・fault-injection timeline | Python driver（`perf/*.py`） | open-loop 自前ペーシング |
| 任意の live dashboard | InfluxDB + Grafana（`docker-compose.yml`） | `INFLUX=1` の時だけ起動（image 取得は setup） |

## シナリオカタログ

各シナリオの subject / generator / 出力 CSV / 読むべき invariant / 対応 ADR。

### Fast path（native）

| phase | subject | generator | 出力 | invariant |
| --- | --- | --- | --- | --- |
| `sweep` | throughput/latency vs concurrency | k6 constant-vus（50–800 VU） | `sweep.csv` | 曲線形（plateau→graceful decline、cliff 無し） |
| `openloop` | coordinated-omission-safe tail | k6 constant-arrival-rate | `openloop.json` | 飽和点での tail 発散 |
| `rr` | round-robin の均等性 | Python（X-Instance 集計） | `rr.csv` | 1 req 精度で 1/3 ずつ |
| `ejection` | health-eject + fail-closed（ADR 000017） | Python fault timeline | `ejection_*.csv` | ~1s 時定数・503 fail-closed・~1s 復帰 |
| `tls` | TLS 終端の分解（h1/keepalive/handshake/h2） | oha | `tls.csv` | record-layer 安い・handshake 支配 |
| `churn` | keep-alive vs cold-connection（TCP handshake/req） | oha（`--disable-keepalive`） | `churn.csv` | connection 再利用の価値 |
| `footprint` | idle RSS + bytes/conn | Python | `footprint.txt` | conn あたり限界バイト |

### Extension plane（WASM filter + host-API）

| phase | subject | generator | 出力 | invariant |
| --- | --- | --- | --- | --- |
| `wasm` | filter overhead（baseline/pooled/on-demand）+ short-circuit | oha + k6 | `wasm_overhead.csv`, `wasm_mixed.csv` | µs/req と pooling の価値（init 再払いの差） |
| `ratelimit` | host token-bucket（ADR 000026）: overhead / enforcement / per-key fairness | k6 | `ratelimit_{overhead,enforce,fairness}.csv` | 許可 rps が refill rate に収束・hot key が light key を starve しない |
| `body` | request-body hook（ADR 000025）の buffer-then-decide コスト + payload sweep | k6 | `body.csv` | hook の payload 比例コスト・streaming passthrough との対比 |

> `ratelimit` と `body` は `examples/edge-bench`（`filter-hello` ベース）で駆動。bucket spec は manifest
> （`RL_CAPACITY` / `RL_REFILL_TOKENS` / `RL_REFILL_INTERVAL_MS`）で host 設定（ADR 000026）。enforcement/
> fairness は tight bucket、overhead は never-deny bucket を流す。

## 実行

```bash
# 前提: release example を build（run-perf.sh は build しない）
cd plecto && cargo build --release -p plecto-server \
  --example load-balancing --example wasm-bench --example tls-http --example edge-bench

# 1 phase か all。proxy を core 集合へ、generator を互いに素な集合へ pin して performance/data/*.csv を出力。
# phases: sweep openloop rr ejection wasm tls ratelimit body churn footprint all
bash bench/perf/run-perf.sh all

# core 集合の override（自ホストの topology に合わせる）
PROXY_CPUS=0-7 GEN_CPUS=8-15 bash bench/perf/run-perf.sh sweep

# 任意: live dashboard（image 取得は setup、負荷は loopback のまま）
INFLUX=1 bash bench/perf/run-perf.sh all   # http://localhost:3000/d/plecto-lb-k6

# CSV からグラフ再生成
python3 performance/plot.py                # performance/data/*.csv -> performance/img/*.webp
```

## 統廃合の経緯

- canonical を `perf/run-perf.sh` に一本化。旧 `run-bench.sh` / `run-wasm-bench.sh`（k6+Grafana 専用 + arm64
  k6 download）と、それらだけが使っていた重複 k6 スクリプト（`k6/lb-load.js` / `lb-rate.js` / `lb-ejection.js`、
  `k6-wasm/route.js`）を撤去。後者は sweep-step / openloop / oha / Python driver が上位互換で代替する。
- Grafana/InfluxDB スタック（`docker-compose.yml` + `grafana/`）は**残置し `INFLUX=1` で opt-in**。run-perf の
  k6 phase が `--out influxdb` で流すので、回帰 baseline（CSV/charts）と live 観測の両方を1本の runner で賄う。

## 出力ファイル

- 追跡（コミット対象）: `performance/data/*.csv`・`performance/img/*.webp`・`performance/README.md`。
- 非追跡（`bench/.gitignore`）: 生 k6/oha 出力・HTML・log・download binary・machine-spec 入りの write-up。
