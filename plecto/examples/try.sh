#!/usr/bin/env bash
# try.sh — run a Plecto example and visualize its behaviour, end to end.
#
#   ./examples/try.sh <name>     name ∈ wasm-auth | load-balancing | filter-chain | tls-http | hot-reload
#   ./examples/try.sh all        run every scenario in turn
#
# It starts the example in the background, waits until it's ready, drives the relevant curl
# scenario, prints the results, and cleans up (kills the process) on exit. Prerequisite (once):
#   rustup target add wasm32-unknown-unknown
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS="$(cd "$HERE/.." && pwd)" # the plecto/ workspace

if [ -t 1 ]; then B=$'\e[1m'; D=$'\e[2m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; R=$'\e[31m'; X=$'\e[0m'
else B=; D=; G=; Y=; C=; R=; X=; fi
say()  { printf '\n%s\n' "${C}${B}━━ $* ━━${X}"; }
note() { printf '%s\n' "${D}# $*${X}"; }
run()  { printf '%s\n' "${Y}\$ $*${X}"; eval "$@"; }
bar()  { local n=$1 s=; while [ "$n" -gt 0 ]; do s="$s█"; n=$((n-1)); done; printf '%s' "$s"; }

NAME=""; PID=""; LOG=""
cleanup() {
  [ -n "$PID" ] && kill "$PID" 2>/dev/null
  [ -n "$NAME" ] && pkill -f "examples/${NAME}$" 2>/dev/null
  [ -n "$LOG" ] && rm -f "$LOG"
}
trap cleanup EXIT INT TERM

start() { # start example $1, stream its output to $LOG, set PID
  NAME="$1"; LOG="$(mktemp)"
  pkill -f "examples/${NAME}$" 2>/dev/null && sleep 0.3 # clear a stale instance from a prior run
  say "starting example: ${B}$NAME${X}${C} (compiling on first run, please wait…)"
  ( cd "$WS" && CARGO_BUILD_JOBS=2 cargo run -q -p plecto-server --example "$NAME" ) >"$LOG" 2>&1 &
  PID=$!
}

wait_ready() { # wait_ready <url> [want-code] [extra curl args…]  — poll until HTTP want (default 200)
  local url="$1"; shift
  local want=200
  [[ "${1:-}" =~ ^[0-9]+$ ]] && { want="$1"; shift; }   # optional explicit want code
  local code i
  printf '%s' "${D}# waiting for ${url} → ${want} ${X}"
  for i in $(seq 300); do
    code="$(curl -s -k "$@" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)"
    [ "$code" = "$want" ] && { printf '%s\n' "${D}ready${X}"; return 0; }
    kill -0 "$PID" 2>/dev/null || { printf '\n%s\n' "${R}example exited early — log:${X}"; cat "$LOG"; return 1; }
    [ $((i % 10)) -eq 0 ] && printf '.'
    sleep 0.2
  done
  printf '\n%s\n' "${R}timed out waiting for ${url} → ${want}${X}"; return 1
}

banner() { sleep 0.3; sed -n '/Plecto demo/,/Try it/p' "$LOG"; } # echo the example's own banner

# ───────────────────────── scenarios ─────────────────────────

scenario_wasm_auth() {
  start wasm-auth
  wait_ready "http://localhost:8084/api/x" -H "x-api-key: alice-secret" || return 1
  banner
  say "no key → 401 (the WASM filter short-circuits; the upstream is never reached)"
  run "curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://localhost:8084/api/data"
  say "unknown key → 401"
  run "curl -s -o /dev/null -w 'HTTP %{http_code}\n' -H 'x-api-key: nope' http://localhost:8084/api/data"
  say "valid keys → 200, greeted by the identity the filter stamped"
  run "curl -s -H 'x-api-key: alice-secret' http://localhost:8084/api/data"
  run "curl -s -H 'x-api-key: bob-secret'   http://localhost:8084/api/data"
  say "spoof attempt: client sends x-authenticated-user: admin — the filter overwrites it"
  run "curl -s -H 'x-api-key: alice-secret' -H 'x-authenticated-user: admin' http://localhost:8084/api/data"
  note "expected: 'hello alice' (not admin)"
}

scenario_load_balancing() {
  start load-balancing
  wait_ready "http://localhost:8080/" || return 1
  banner
  local b; b="$(grep -oE 'inst  : b -> http://[0-9.]+:[0-9]+' "$LOG" | grep -oE '[0-9.]+:[0-9]+' | head -1)"
  tally() { # hit the proxy $1 times, show the per-instance distribution as bars
    local n="$1" inst; declare -A c=();
    for _ in $(seq "$n"); do
      inst="$(curl -s http://localhost:8080/ | grep -oE 'instance [abc]' | awk '{print $2}')"
      [ -n "$inst" ] && c[$inst]=$(( ${c[$inst]:-0} + 1 ))
    done
    for k in a b c; do printf '  %s │ %s %s\n' "$k" "${G}$(bar "${c[$k]:-0}")${X}" "(${c[$k]:-0})"; done
  }
  say "round-robin over 3 healthy instances (12 requests)"
  tally 12
  say "drive instance b unhealthy:  curl http://$b/toggle  (then wait for the prober to eject it)"
  run "curl -s http://$b/toggle"; sleep 1.5
  say "same 12 requests — b is ejected, traffic splits over a and c only"
  tally 12
  say "recover b:  curl http://$b/toggle  (then wait for it to rejoin)"
  run "curl -s http://$b/toggle"; sleep 1.5
  say "b is back in rotation"
  tally 12
  say "toggle ALL three off → no healthy instance → fail-closed 503"
  for a in $(grep -oE 'http://[0-9.]+:[0-9]+   \(/healthz' "$LOG" | grep -oE '[0-9.]+:[0-9]+'); do curl -s "http://$a/toggle" >/dev/null; done
  sleep 1.5
  run "curl -s -o /dev/null -w 'HTTP %{http_code}  ' http://localhost:8080/; curl -s -i http://localhost:8080/ | grep -i x-plecto-fault"
}

scenario_filter_chain() {
  start filter-chain
  wait_ready "http://localhost:8081/api/hello" || return 1
  banner
  say "continue: forwarded, and the response gains x-plecto-respadded (response-side chain)"
  run "curl -s -D - -o /dev/null http://localhost:8081/api/hello | grep -iE 'HTTP/|x-plecto-respadded'"
  say "modify: the filter adds x-plecto-added, which the upstream echoes back in the body"
  run "curl -s -H 'x-plecto-addheader: 1' http://localhost:8081/api/hello"
  say "short-circuit: 403, the upstream is never reached"
  run "curl -s -o /dev/null -w 'HTTP %{http_code}\n' -H 'x-plecto-block: 1' http://localhost:8081/api/hello"
  say "host-native rate limit (token bucket capacity 2): 200, 200, 429"
  run "for i in 1 2 3; do curl -s -o /dev/null -w 'HTTP %{http_code}\n' -H 'x-plecto-ratelimit: 1' http://localhost:8081/api/hello; done"
}

scenario_tls_http() {
  start tls-http
  wait_ready "https://localhost:8443/api/hello" || return 1
  banner
  say "HTTP/1.1 over TLS"
  run "curl -sk --http1.1 -o /dev/null -w 'negotiated HTTP/%{http_version}\n' https://localhost:8443/api/hello"
  say "HTTP/2 over TLS (ALPN h2)"
  run "curl -sk --http2 -o /dev/null -w 'negotiated HTTP/%{http_version}\n' https://localhost:8443/api/hello"
  say "Alt-Svc advertises HTTP/3 on the same port"
  run "curl -sk -D - -o /dev/null https://localhost:8443/api/hello | grep -i alt-svc"
  if curl --version | grep -qi 'HTTP3'; then
    say "HTTP/3 over QUIC"
    run "curl -sk --http3 -o /dev/null -w 'negotiated HTTP/%{http_version}\n' https://localhost:8443/api/hello"
  else
    note "your curl has no HTTP/3 support — skipping --http3 (h1/h2 above already prove TLS termination)"
  fi
}

scenario_hot_reload() {
  start hot-reload
  wait_ready "http://localhost:8082/api/hello" || return 1
  banner
  local pid manifest
  pid="$(grep -oE 'pid      : [0-9]+' "$LOG" | grep -oE '[0-9]+' | head -1)"
  manifest="$(grep -E 'manifest : ' "$LOG" | head -1 | sed 's/.*manifest : //')"
  note "pid=$pid  manifest=$manifest"
  say "baseline: strip_prefix=\"/api\", so the upstream sees /hello"
  run "curl -s http://localhost:8082/api/hello"
  say "edit the manifest (strip_prefix \"/api\" → \"/\") and SIGHUP — no restart"
  run "sed -i 's|strip_prefix = \"/api\"|strip_prefix = \"/\"|' '$manifest'"
  run "kill -HUP $pid"; sleep 0.8
  say "same request — the reloaded config now forwards the full path"
  run "curl -s http://localhost:8082/api/hello"
  note "expected: 'upstream received: /api/hello'"
}

# ───────────────────────── dispatch ─────────────────────────

one() {
  case "$1" in
    wasm-auth)      scenario_wasm_auth ;;
    load-balancing) scenario_load_balancing ;;
    filter-chain)   scenario_filter_chain ;;
    tls-http)       scenario_tls_http ;;
    hot-reload)     scenario_hot_reload ;;
    *) echo "unknown example: $1"; usage; exit 1 ;;
  esac
  say "done — stopping $NAME"
  cleanup; PID=""; NAME=""; LOG=""
}

usage() {
  cat <<EOF
${B}Plecto demo runner${X}
  $0 wasm-auth        a real WASM filter: API-key auth (401 / identity / anti-spoof)
  $0 load-balancing   round-robin + active health eject/restore + 503 (visualized)
  $0 filter-chain     continue / modify / short-circuit 403 / rate-limit
  $0 tls-http         TLS termination across HTTP/1.1, HTTP/2, HTTP/3 + Alt-Svc
  $0 hot-reload       edit manifest + SIGHUP → atomic zero-downtime swap (before/after)
  $0 all              run every scenario in turn
EOF
}

case "${1:-}" in
  "" ) usage ;;
  all) for s in wasm-auth load-balancing filter-chain tls-http hot-reload; do one "$s"; done ;;
  *  ) one "$1" ;;
esac
