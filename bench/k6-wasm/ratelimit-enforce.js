// Rate-limit ENFORCEMENT accuracy (ADR 000026). Open-loop: offer a fixed arrival rate well above the
// bucket's steady refill rate against ONE key, so the host-native token bucket must shed the excess.
// The signal: after the initial burst (~capacity) drains, the ALLOWED throughput converges to the
// configured refill rate (refill_tokens / refill_interval), and the rest is short-circuited 429 at
// the edge (never reaching upstream). constant-arrival-rate keeps offering load regardless of 429s,
// so the enforcement is measured honestly (coordinated-omission-safe).
import http from "k6/http";
import { Counter, Trend } from "k6/metrics";

const BASE = __ENV.BASE || "http://localhost:8086";
const RATE = Number(__ENV.RATE || 5000);
const DUR = __ENV.DUR || "30s";
const KEY = __ENV.KEY || "enforce";
const OUT = __ENV.OUT || "ratelimit_enforce.json";

const accepted = new Counter("accepted");
const limited = new Counter("limited");
const latAccept = new Trend("lat_accept", true);
const latLimit = new Trend("lat_limit", true);

export const options = {
  summaryTrendStats: ["avg", "med", "p(95)", "p(99)", "max"],
  scenarios: {
    enforce: {
      executor: "constant-arrival-rate",
      rate: RATE,
      timeUnit: "1s",
      duration: DUR,
      preAllocatedVUs: Math.max(200, Math.ceil(RATE / 10)),
      maxVUs: Math.max(1000, RATE),
    },
  },
};

export default function () {
  const res = http.get(`${BASE}/ratelimit/x`, { headers: { "x-plecto-ratelimit": KEY } });
  if (res.status === 200) {
    accepted.add(1);
    latAccept.add(res.timings.duration);
  } else if (res.status === 429) {
    limited.add(1);
    latLimit.add(res.timings.duration);
  }
}

export function handleSummary(data) {
  const secs = (data.state.testRunDurationMs || 1) / 1000;
  const acc = data.metrics.accepted ? data.metrics.accepted.values.count : 0;
  const lim = data.metrics.limited ? data.metrics.limited.values.count : 0;
  const a = data.metrics.lat_accept ? data.metrics.lat_accept.values : {};
  const l = data.metrics.lat_limit ? data.metrics.lat_limit.values : {};
  const out = {
    target_rps: RATE,
    achieved_rps: data.metrics.http_reqs.values.rate,
    accepted: acc,
    limited: lim,
    allowed_rps: acc / secs,
    limited_frac: lim / Math.max(1, acc + lim),
    accept_p50: a.med || 0,
    accept_p99: a["p(99)"] || 0,
    limit_p50: l.med || 0,
    limit_p99: l["p(99)"] || 0,
  };
  const line =
    `\nenforce ${RATE}/s -> allowed ${out.allowed_rps.toFixed(0)}/s ` +
    `(${acc} ok / ${lim} 429, ${(out.limited_frac * 100).toFixed(1)}% shed)  ` +
    `accept p99=${out.accept_p99.toFixed(2)}ms  429 p99=${out.limit_p99.toFixed(2)}ms\n`;
  return { [OUT]: JSON.stringify(out, null, 2), stdout: line };
}
