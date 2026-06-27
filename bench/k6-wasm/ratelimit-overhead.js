// Rate-limit OVERHEAD on the hot path (ADR 000026). With a generous bucket that never denies, measure
// the cost of consulting the host-native token bucket on every request versus the no-filter baseline.
// Closed-loop at fixed concurrency; requests spread across KEYS distinct bucket keys (realistic multi-
// tenant load, low single-key contention). Run once per ROUTE (/baseline vs /ratelimit); the rps / p99
// delta is the limiter's per-request tax. (Pair with a never-deny bucket via RL_* on the example.)
import http from "k6/http";
import { check } from "k6";

const BASE = __ENV.BASE || "http://localhost:8086";
const ROUTE = __ENV.ROUTE_PATH || "/baseline";
const KEYS = Number(__ENV.KEYS || 1000);
const VUS = Number(__ENV.VUS || 50);
const DUR = __ENV.DUR || "30s";
const OUT = __ENV.OUT || "ratelimit_overhead.json";

export const options = {
  summaryTrendStats: ["avg", "min", "med", "p(90)", "p(95)", "p(99)", "max"],
  scenarios: { fixed: { executor: "constant-vus", vus: VUS, duration: DUR } },
};

export default function () {
  // /baseline ignores the header; /ratelimit consults the bucket at this key. Spreading over KEYS
  // keys keeps per-key contention realistic rather than hammering one bucket's state.
  const params =
    ROUTE === "/baseline"
      ? {}
      : { headers: { "x-plecto-ratelimit": `k${(__ITER % KEYS)}` } };
  const res = http.get(`${BASE}${ROUTE}/x`, params);
  check(res, { "status 200": (r) => r.status === 200 });
}

export function handleSummary(data) {
  const d = data.metrics.http_req_duration.values;
  const out = {
    route: ROUTE,
    vus: VUS,
    keys: ROUTE === "/baseline" ? 0 : KEYS,
    rps: data.metrics.http_reqs.values.rate,
    reqs: data.metrics.http_reqs.values.count,
    failed_rate: data.metrics.http_req_failed.values.rate,
    p50: d.med, p90: d["p(90)"], p95: d["p(95)"], p99: d["p(99)"],
  };
  const line =
    `\n${ROUTE}: ${out.rps.toFixed(0)} rps  p50=${out.p50.toFixed(3)}ms ` +
    `p99=${out.p99.toFixed(3)}ms  fail=${(out.failed_rate * 100).toFixed(2)}%\n`;
  return { [OUT]: JSON.stringify(out, null, 2), stdout: line };
}
