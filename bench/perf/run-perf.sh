#!/usr/bin/env bash
# Plecto perf runbook — emits performance/data/*.csv consumed by performance/plot.py. Fully local,
# loopback. Plecto (+ its in-process backends) is pinned to one set of CPU cores and every load
# generator to a disjoint set via taskset, so the generator never steals the proxy's cores. No host
# tuning is applied (governor/turbo left as-is), so absolute throughput is bounded by this host and
# the generator; read ratios, shapes and time-constants as the signal.
#
#   bash bench/perf/run-perf.sh <phase>    phase ∈ sweep openloop rr ejection wasm tls footprint all
#
# Default ports avoid colliding with other local services (override with *_ADDR env).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$BENCH/.." && pwd)"
WS="$ROOT/plecto"
DATA="$ROOT/performance/data"
mkdir -p "$DATA"

OHA="${OHA:-$HOME/.cargo/bin/oha}"
K6="${K6:-$(command -v k6)}"
# Pin Plecto and the generators to disjoint core sets. Default: split the logical CPUs in half —
# proxy on the lower indices, generators on the upper. Override PROXY_CPUS / GEN_CPUS to match your
# host's topology (e.g. put the proxy on its fastest cores and the generators on the rest).
_NCPU="$(nproc)"; _HALF="$(( _NCPU / 2 ))"
PROXY_CPUS="${PROXY_CPUS:-0-$(( _HALF - 1 ))}"
GEN_CPUS="${GEN_CPUS:-$_HALF-$(( _NCPU - 1 ))}"
export K6_NO_USAGE_REPORT=true

LB_ADDR="${LB_ADDR:-127.0.0.1:28080}"
WASM_ADDR="${WASM_ADDR:-127.0.0.1:28085}"
TLS_ADDR="${TLS_ADDR:-127.0.0.1:28443}"
EDGE_ADDR="${EDGE_ADDR:-127.0.0.1:28086}"

log(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
gen(){ taskset -c "$GEN_CPUS" "$@"; }   # run a generator on the generator core set

# Optional live dashboard (opt-in): INFLUX=1 brings up the local InfluxDB+Grafana stack
# (bench/docker-compose.yml) and streams every k6 phase to it, so a run is watchable in real time at
# http://localhost:3000. Pulling the two images is a one-time SETUP fetch; the load itself stays
# fully on loopback (generators + proxy + in-process upstreams), telemetry off. Unset (default) =
# no docker, CSV + matplotlib charts only.
INFLUX_OUT=()
influx_down(){ :; }
if [[ "${INFLUX:-}" == "1" ]]; then
  COMPOSE=(docker compose -f "$BENCH/docker-compose.yml")
  influx_down(){ "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true; }
  log "INFLUX=1 — bringing up the local InfluxDB + Grafana dashboard (one-time image pull)"
  "${COMPOSE[@]}" up -d
  for _ in $(seq 60); do curl -fsS "http://localhost:8086/ping" >/dev/null 2>&1 && break; sleep 1; done
  curl -fsS -XPOST "http://localhost:8086/query" --data-urlencode "q=DROP DATABASE k6"   >/dev/null 2>&1 || true
  curl -fsS -XPOST "http://localhost:8086/query" --data-urlencode "q=CREATE DATABASE k6" >/dev/null 2>&1 || true
  INFLUX_OUT=(--out "influxdb=http://localhost:8086/k6")
  echo "  Grafana: http://localhost:3000/d/plecto-lb-k6  (anonymous Admin)"
fi

PROXY_PID=""
BLOG=""
stop_proxy(){ [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null; PROXY_PID=""; }
trap 'stop_proxy; influx_down' EXIT

# launch <example> <addr> <health_url|""> [env KEY=VAL ...]
# health_url empty => skip the http health loop (caller probes itself, e.g. TLS over https).
launch(){
  local ex="$1" addr="$2" health="$3"; shift 3
  BLOG="$(mktemp)"
  env PLECTO_PROXY_ADDR="$addr" RUST_LOG=warn "$@" "$WS/target/release/examples/$ex" >"$BLOG" 2>&1 &
  PROXY_PID=$!
  taskset -cp "$PROXY_CPUS" "$PROXY_PID" >/dev/null 2>&1
  if [[ -n "$health" ]]; then
    local ok=""
    for _ in $(seq 80); do curl -fsS "$health" >/dev/null 2>&1 && { ok=1; break; }; sleep 0.25; done
    [[ -n "$ok" ]] || { echo "proxy $ex did not become healthy"; cat "$BLOG"; return 1; }
  else
    sleep 2
  fi
  echo "launched $ex on $addr (pid $PROXY_PID, pinned $PROXY_CPUS)"
}

# oha JSON (latency in seconds) -> "rps p50 p90 p95 p99 p99_9" in ms
oha_row(){ python3 "$HERE/oha_parse.py" "$1"; }

# ---------------------------------------------------------------- Phase 2.1 sweep
phase_sweep(){
  log "Phase 2.1 — closed-loop sweep (k6 constant-vus) -> sweep.csv"
  launch load-balancing "$LB_ADDR" "http://$LB_ADDR/" || return 1
  local tmp; tmp="$(mktemp -d)"
  for vus in 50 100 200 400 800; do
    log "  VU=$vus"
    gen "$K6" run -q "${INFLUX_OUT[@]}" \
      -e TARGET="http://$LB_ADDR/" -e VUS=$vus -e DUR=60s -e OUT="$tmp/vu$vus.json" \
      "$BENCH/k6/lb-sweep-step.js" 2>&1 | tail -1
  done
  stop_proxy
  python3 -c '
import json,glob,csv,os,sys
rows=[]
for f in sorted(glob.glob(os.path.join(sys.argv[1],"vu*.json")), key=lambda p:int(p.split("vu")[-1].split(".")[0])):
    d=json.load(open(f)); rows.append(d)
with open(sys.argv[2],"w",newline="") as o:
    w=csv.writer(o); w.writerow(["vus","rps","p50","p95","p99","p99_9","failed"])
    for d in rows:
        w.writerow([d["vus"],round(d["rps"],1),round(d["p50"],3),round(d["p95"],3),
                    round(d["p99"],3),round(d["p99_9"],3),round(d["failed"],5)])
print("wrote sweep.csv")
' "$tmp" "$DATA/sweep.csv"
  cat "$DATA/sweep.csv"
}

# ---------------------------------------------------------------- Phase 2.2 open-loop tail
phase_openloop(){
  log "Phase 2.2 — open-loop tail at ~70% of closed-loop peak -> openloop.json"
  local peak rate
  peak="$(python3 -c 'import json,csv,sys; rows=list(csv.DictReader(open(sys.argv[1]))); print(int(max(float(r["rps"]) for r in rows)))' "$DATA/sweep.csv" 2>/dev/null || echo 0)"
  # The closed-loop peak is the *generator's* ceiling, not the proxy's; open-loop generation
  # saturates lower, so OPENLOOP_RATE lets us pin a rate the generator sustains cleanly (a
  # drowned generator inflates the tail with its own queueing, not the proxy's). Default 70%.
  rate="${OPENLOOP_RATE:-$(python3 -c "print(max(500,int($peak*0.7)))")}"
  echo "  closed-loop peak≈${peak} rps -> open-loop rate=${rate} rps"
  launch load-balancing "$LB_ADDR" "http://$LB_ADDR/" || return 1
  gen "$K6" run -q "${INFLUX_OUT[@]}" \
    -e TARGET="http://$LB_ADDR/" -e RATE=$rate -e DUR=90s -e OUT="$DATA/openloop.json" \
    "$BENCH/k6/lb-openloop.js" 2>&1 | tail -2
  stop_proxy
  cat "$DATA/openloop.json"
}

# ---------------------------------------------------------------- Phase 2.3 round-robin
phase_rr(){
  log "Phase 2.3 — round-robin distribution -> rr.csv"
  launch load-balancing "$LB_ADDR" "http://$LB_ADDR/" || return 1
  gen python3 "$HERE/rr_count.py" --target "http://$LB_ADDR/" --total 120000 --workers 48 --out "$DATA/rr.csv"
  stop_proxy
  cat "$DATA/rr.csv"
}

# ---------------------------------------------------------------- Phase 2.4 resilience
phase_ejection(){
  log "Phase 2.4 — fault injection timeline -> ejection_timeline.csv + ejection_events.csv"
  launch load-balancing "$LB_ADDR" "http://$LB_ADDR/" || return 1
  local be; be=($(grep -oE 'http://127\.0\.0\.1:[0-9]+' "$BLOG" | head -3))
  [[ "${#be[@]}" -eq 3 ]] || { echo "expected 3 backends, got ${be[*]:-none}"; stop_proxy; return 1; }
  echo "  backends: a=${be[0]} b=${be[1]} c=${be[2]}"
  gen python3 "$HERE/ejection_driver.py" --target "http://$LB_ADDR/" --rate 4000 --duration 75 --workers 64 \
    --toggle "a=${be[0]}/toggle" "b=${be[1]}/toggle" "c=${be[2]}/toggle" \
    --out "$DATA/ejection_timeline.csv" --events-out "$DATA/ejection_events.csv"
  stop_proxy
  echo "--- events ---"; cat "$DATA/ejection_events.csv"
  echo "--- timeline head/tail ---"; head -3 "$DATA/ejection_timeline.csv"; tail -3 "$DATA/ejection_timeline.csv"
}

# ---------------------------------------------------------------- Phase 3 WASM
phase_wasm(){
  log "Phase 3.1 — WASM overhead (oha 50c, 0 ms backend) -> wasm_overhead.csv"
  launch wasm-bench "$WASM_ADDR" "http://$WASM_ADDR/baseline/x" BACKEND_LATENCY_MS=0 || return 1
  local tmp; tmp="$(mktemp -d)"
  for r in baseline trusted ondemand; do
    local hdr=(); [[ "$r" != baseline ]] && hdr=(-H "x-api-key: alice-secret")
    gen "$OHA" -z 60s -c 50 --no-tui --output-format json "${hdr[@]}" \
      "http://$WASM_ADDR/$r/x" > "$tmp/$r.json" 2>/dev/null
    echo "  /$r -> $(oha_row "$tmp/$r.json")"
  done
  stop_proxy
  { echo "route,rps,p50,p90,p95,p99"
    for r in baseline trusted ondemand; do
      read -r rps p50 p90 p95 p99 _ <<<"$(oha_row "$tmp/$r.json")"
      echo "$r,$rps,$p50,$p90,$p95,$p99"
    done; } > "$DATA/wasm_overhead.csv"
  cat "$DATA/wasm_overhead.csv"

  log "Phase 3.3 — short-circuit mixed (k6 2000 rps, 15 ms backend, 90/10) -> wasm_mixed.csv"
  launch wasm-bench "$WASM_ADDR" "http://$WASM_ADDR/baseline/x" BACKEND_LATENCY_MS=15 || return 1
  gen "$K6" run -q "${INFLUX_OUT[@]}" -e BASE="http://$WASM_ADDR" -e RATE=2000 -e DUR=60s -e OUT="$tmp/mixed.json" \
    "$BENCH/k6-wasm/mixed.js" 2>&1 | tail -2
  stop_proxy
  python3 -c '
import json,csv,sys
d=json.load(open(sys.argv[1])); dur=float(sys.argv[3])
with open(sys.argv[2],"w",newline="") as o:
    w=csv.writer(o); w.writerow(["outcome","rps","p50","p95","p99","count"])
    w.writerow(["accept",round(d["accepted"]/dur,1),round(d["accept_p50"],3),round(d["accept_p95"],3),round(d["accept_p99"],3),d["accepted"]])
    w.writerow(["reject",round(d["rejected"]/dur,1),round(d["reject_p50"],3),round(d["reject_p95"],3),round(d["reject_p99"],3),d["rejected"]])
print("wrote wasm_mixed.csv")
' "$tmp/mixed.json" "$DATA/wasm_mixed.csv" 60
  cat "$DATA/wasm_mixed.csv"
}

# ---------------------------------------------------------------- Phase 4 TLS
phase_tls(){
  log "Phase 4 — TLS decomposition (oha) -> tls.csv"
  local tmp; tmp="$(mktemp -d)"
  # plain h1 baseline: the wasm-bench /baseline route (single backend, no filter, plaintext h1).
  launch wasm-bench "$WASM_ADDR" "http://$WASM_ADDR/baseline/x" BACKEND_LATENCY_MS=0 || return 1
  gen "$OHA" -z 30s -c 50 --no-tui --output-format json "http://$WASM_ADDR/baseline/x" > "$tmp/plain.json" 2>/dev/null
  echo "  plain (h1)        -> $(oha_row "$tmp/plain.json")"
  stop_proxy
  # tls-http: /api/hello over TLS. B=h1 keepalive, C=h1 handshake-per-request, D=h2.
  launch tls-http "$TLS_ADDR" "" || return 1
  # health over https (self-signed): tolerant probe before measuring.
  for _ in $(seq 40); do gen "$OHA" -n 1 --insecure --no-tui "https://$TLS_ADDR/api/hello" >/dev/null 2>&1 && break; sleep 0.25; done
  gen "$OHA" -z 30s -c 50 --no-tui --insecure --output-format json "https://$TLS_ADDR/api/hello" > "$tmp/tls_h1_ka.json" 2>/dev/null
  echo "  tls h1 keepalive  -> $(oha_row "$tmp/tls_h1_ka.json")"
  gen "$OHA" -z 30s -c 50 --no-tui --insecure --disable-keepalive --output-format json "https://$TLS_ADDR/api/hello" > "$tmp/tls_h1_hs.json" 2>/dev/null
  echo "  tls h1 handshake  -> $(oha_row "$tmp/tls_h1_hs.json")"
  gen "$OHA" -z 30s -c 50 --no-tui --insecure --http2 --output-format json "https://$TLS_ADDR/api/hello" > "$tmp/tls_h2.json" 2>/dev/null
  echo "  tls (h2)          -> $(oha_row "$tmp/tls_h2.json")"
  stop_proxy
  { echo "variant,rps,p50,p99"
    add(){ read -r rps p50 _ _ p99 _ <<<"$(oha_row "$2")"; echo "$1,$rps,$p50,$p99"; }
    add "plain (h1)" "$tmp/plain.json"
    add "tls h1 keepalive" "$tmp/tls_h1_ka.json"
    add "tls h1 handshake" "$tmp/tls_h1_hs.json"
    add "tls (h2)" "$tmp/tls_h2.json"; } > "$DATA/tls.csv"
  cat "$DATA/tls.csv"
}

# ---------------------------------------------------------------- Phase 5 footprint
phase_footprint(){
  log "Phase 5 — footprint (idle RSS, bytes/conn) -> footprint.txt"
  launch wasm-bench "$WASM_ADDR" "http://$WASM_ADDR/baseline/x" BACKEND_LATENCY_MS=0 || return 1
  sleep 2
  local idle; idle="$(grep VmRSS /proc/$PROXY_PID/status | awk '{print $2}')"  # kB
  echo "idle VmRSS: ${idle} kB" | tee "$DATA/footprint.txt"
  # hold K steady keep-alive connections and re-read RSS
  local wh="${WASM_ADDR%:*}" wp="${WASM_ADDR##*:}"
  gen python3 -c '
import http.client,sys,time
host,port,K=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
conns=[]
for _ in range(K):
    c=http.client.HTTPConnection(host,port); c.request("GET","/baseline/x"); c.getresponse().read(); conns.append(c)
time.sleep(6)
' "$wh" "$wp" 1000 &
  HOLD=$!
  sleep 3
  local busy; busy="$(grep VmRSS /proc/$PROXY_PID/status | awk '{print $2}')"
  wait $HOLD 2>/dev/null
  echo "RSS with ~1000 conns: ${busy} kB" | tee -a "$DATA/footprint.txt"
  python3 -c "print(f'bytes/conn ≈ {($busy-$idle)*1024/1000:.0f}')" | tee -a "$DATA/footprint.txt"
  stop_proxy
}

# ---------------------------------------------------------------- Phase 6 rate limit (ADR 000026)
phase_ratelimit(){
  local tmp; tmp="$(mktemp -d)"
  # -- 6.1 overhead: a generous (never-deny) bucket isolates the limiter's hot-path cost. Spread the
  # load across many keys (realistic multi-tenant), compare /ratelimit vs the no-filter /baseline. --
  log "Phase 6.1 — rate-limit overhead (generous bucket, multi-key) -> ratelimit_overhead.csv"
  launch edge-bench "$EDGE_ADDR" "http://$EDGE_ADDR/baseline/x" || return 1
  for rt in baseline ratelimit; do
    gen "$K6" run -q "${INFLUX_OUT[@]}" -e BASE="http://$EDGE_ADDR" -e ROUTE_PATH="/$rt" \
      -e KEYS=1000 -e VUS=50 -e DUR=30s -e OUT="$tmp/ov_$rt.json" \
      "$BENCH/k6-wasm/ratelimit-overhead.js" 2>&1 | tail -1
  done
  stop_proxy
  python3 -c '
import json,csv,sys
with open(sys.argv[3],"w",newline="") as o:
    w=csv.writer(o); w.writerow(["route","rps","p50","p99"])
    for f in sys.argv[1:3]:
        d=json.load(open(f)); w.writerow([d["route"],round(d["rps"],1),round(d["p50"],3),round(d["p99"],3)])
' "$tmp/ov_baseline.json" "$tmp/ov_ratelimit.json" "$DATA/ratelimit_overhead.csv"
  cat "$DATA/ratelimit_overhead.csv"

  # -- 6.2 enforcement + fairness: a TIGHT bucket (refill 1000/s, burst 2000) host-set in the manifest.
  # Offer well above the limit and watch the allowed rate converge to the refill rate; a hot key must
  # not starve a light one (independent per-key state). --
  log "Phase 6.2 — enforcement + fairness (tight bucket, refill 1000/s) -> ratelimit_{enforce,fairness}.csv"
  launch edge-bench "$EDGE_ADDR" "http://$EDGE_ADDR/baseline/x" \
    RL_CAPACITY=2000 RL_REFILL_TOKENS=1000 RL_REFILL_INTERVAL_MS=1000 || return 1
  gen "$K6" run -q "${INFLUX_OUT[@]}" -e BASE="http://$EDGE_ADDR" -e RATE=5000 -e DUR=30s \
    -e OUT="$tmp/enforce.json" "$BENCH/k6-wasm/ratelimit-enforce.js" 2>&1 | tail -1
  gen "$K6" run -q "${INFLUX_OUT[@]}" -e BASE="http://$EDGE_ADDR" -e HOT_RATE=4000 -e LIGHT_RATE=500 \
    -e DUR=30s -e OUT="$tmp/fairness.json" "$BENCH/k6-wasm/ratelimit-fairness.js" 2>&1 | tail -1
  stop_proxy
  python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
print("metric,value")
for k in ("target_rps","achieved_rps","allowed_rps","limited_frac","accept_p50","accept_p99","limit_p99","accepted","limited"):
    print(f"{k},{round(d[k],3)}")
' "$tmp/enforce.json" > "$DATA/ratelimit_enforce.csv"
  python3 -c '
import json,csv,sys
d=json.load(open(sys.argv[1]))
with open(sys.argv[2],"w",newline="") as o:
    w=csv.writer(o); w.writerow(["key","offered_rps","allowed_rps","shed_frac"])
    hot_shed=d["hot_429"]/max(1,d["hot_ok"]+d["hot_429"])
    w.writerow(["hot",d["hot_offered_rps"],round(d["hot_allowed_rps"],1),round(hot_shed,4)])
    w.writerow(["light",d["light_offered_rps"],round(d["light_allowed_rps"],1),round(d["light_429_frac"],4)])
' "$tmp/fairness.json" "$DATA/ratelimit_fairness.csv"
  echo "--- enforce ---"; cat "$DATA/ratelimit_enforce.csv"
  echo "--- fairness ---"; cat "$DATA/ratelimit_fairness.csv"
}

# ---------------------------------------------------------------- Phase 7 request body (ADR 000025)
phase_body(){
  log "Phase 7 — request-body hook overhead + payload sweep -> body.csv"
  launch edge-bench "$EDGE_ADDR" "http://$EDGE_ADDR/baseline/x" || return 1
  local tmp; tmp="$(mktemp -d)"
  local rss=""
  { echo "size,route,rps,req_mbps,p50,p99"
    for size in 1024 102400 1048576; do
      for rt in baseline body; do
        gen "$K6" run -q "${INFLUX_OUT[@]}" -e BASE="http://$EDGE_ADDR" -e ROUTE_PATH="/$rt" \
          -e SIZE=$size -e VUS=50 -e DUR=20s -e OUT="$tmp/b_${size}_$rt.json" \
          "$BENCH/k6-wasm/body-transform.js" >/dev/null 2>&1
        python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
print("%d,%s,%.1f,%.2f,%.3f,%.3f"%(d["size"],d["route"],d["rps"],d["req_mbps"],d["p50"],d["p99"]))
' "$tmp/b_${size}_$rt.json"
        # Sample the proxy's RSS right after the largest /body run to size the buffer-then-decide cost.
        [[ "$size" == 1048576 && "$rt" == body ]] && rss="$(grep VmRSS /proc/$PROXY_PID/status | awk '{print $2}')"
      done
    done; } > "$DATA/body.csv"
  stop_proxy
  cat "$DATA/body.csv"
  [[ -n "$rss" ]] && echo "VmRSS during 1MB /body (50 VUs): ${rss} kB"
}

# ---------------------------------------------------------------- Phase 8 connection churn
phase_churn(){
  log "Phase 8 — connection churn: keep-alive vs cold-connection (plain h1) -> churn.csv"
  launch edge-bench "$EDGE_ADDR" "http://$EDGE_ADDR/baseline/x" || return 1
  local tmp; tmp="$(mktemp -d)"
  gen "$OHA" -z 30s -c 50 --no-tui --output-format json "http://$EDGE_ADDR/baseline/x" > "$tmp/ka.json" 2>/dev/null
  echo "  keep-alive        -> $(oha_row "$tmp/ka.json")"
  gen "$OHA" -z 30s -c 50 --no-tui --disable-keepalive --output-format json "http://$EDGE_ADDR/baseline/x" > "$tmp/cold.json" 2>/dev/null
  echo "  cold (TCP/req)    -> $(oha_row "$tmp/cold.json")"
  stop_proxy
  { echo "variant,rps,p50,p99"
    add(){ read -r rps p50 _ _ p99 _ <<<"$(oha_row "$2")"; echo "$1,$rps,$p50,$p99"; }
    add "keep-alive" "$tmp/ka.json"
    add "cold (TCP/req)" "$tmp/cold.json"; } > "$DATA/churn.csv"
  cat "$DATA/churn.csv"
}

case "${1:-all}" in
  sweep) phase_sweep;; openloop) phase_openloop;; rr) phase_rr;; ejection) phase_ejection;;
  wasm) phase_wasm;; tls) phase_tls;; footprint) phase_footprint;;
  ratelimit) phase_ratelimit;; body) phase_body;; churn) phase_churn;;
  all) phase_sweep; phase_openloop; phase_rr; phase_ejection; phase_wasm; phase_tls; \
       phase_ratelimit; phase_body; phase_churn; phase_footprint;;
  *) echo "unknown phase: $1"; exit 2;;
esac
log "done: $1"
