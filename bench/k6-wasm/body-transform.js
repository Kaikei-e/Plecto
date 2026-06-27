// Request-body hook overhead + payload-size scaling (ADR 000025). POST a SIZE-byte body to a route and
// measure throughput / tail. On /body the host buffers the whole body and runs `on-request-body`
// (filter-hello uppercases it) before forwarding; on /baseline the body streams straight through. The
// /body-vs-/baseline delta at each SIZE is the buffer-then-decide cost, and how it scales with payload.
import http from "k6/http";
import { check } from "k6";

const BASE = __ENV.BASE || "http://localhost:8086";
const ROUTE = __ENV.ROUTE_PATH || "/baseline";
const SIZE = Number(__ENV.SIZE || 1024);
const VUS = Number(__ENV.VUS || 50);
const DUR = __ENV.DUR || "20s";
const OUT = __ENV.OUT || "body.json";

// Lowercase payload so the transform on /body is real work (uppercasing) rather than a no-op.
const PAYLOAD = "a".repeat(SIZE);

export const options = {
  summaryTrendStats: ["avg", "min", "med", "p(90)", "p(95)", "p(99)", "max"],
  scenarios: { fixed: { executor: "constant-vus", vus: VUS, duration: DUR } },
};

export default function () {
  const res = http.post(`${BASE}${ROUTE}/x`, PAYLOAD);
  check(res, { "status 200": (r) => r.status === 200 });
}

export function handleSummary(data) {
  const secs = (data.state.testRunDurationMs || 1) / 1000;
  const d = data.metrics.http_req_duration.values;
  const reqs = data.metrics.http_reqs.values.count;
  const out = {
    route: ROUTE,
    size: SIZE,
    vus: VUS,
    rps: data.metrics.http_reqs.values.rate,
    // request-body throughput in MB/s (the buffered/streamed payload), the I/O-bound signal at scale.
    req_mbps: (reqs * SIZE) / secs / 1e6,
    failed_rate: data.metrics.http_req_failed.values.rate,
    p50: d.med, p95: d["p(95)"], p99: d["p(99)"],
  };
  const line =
    `\n${ROUTE} ${SIZE}B: ${out.rps.toFixed(0)} rps  ${out.req_mbps.toFixed(1)} MB/s  ` +
    `p50=${out.p50.toFixed(3)}ms p99=${out.p99.toFixed(3)}ms  fail=${(out.failed_rate * 100).toFixed(2)}%\n`;
  return { [OUT]: JSON.stringify(out, null, 2), stdout: line };
}
