// Rate-limit FAIRNESS across keys (ADR 000026). The host bucket is per-filter, per-key: each distinct
// `x-plecto-ratelimit` value gets its OWN independent token state. So a heavy key that exceeds the
// limit must be throttled to its own refill rate WITHOUT starving a light key sharing the same filter.
// Two concurrent open-loop streams — a HOT key offered far above the limit and a LIGHT key offered
// below it — prove the isolation: HOT is shed to ~refill rate (many 429), LIGHT passes cleanly (~0 429).
import http from "k6/http";
import { Counter } from "k6/metrics";

const BASE = __ENV.BASE || "http://localhost:8086";
const HOT_RATE = Number(__ENV.HOT_RATE || 4000);
const LIGHT_RATE = Number(__ENV.LIGHT_RATE || 500);
const DUR = __ENV.DUR || "30s";
const OUT = __ENV.OUT || "ratelimit_fairness.json";

const hotOk = new Counter("hot_ok");
const hot429 = new Counter("hot_429");
const lightOk = new Counter("light_ok");
const light429 = new Counter("light_429");

export const options = {
  scenarios: {
    hot: {
      executor: "constant-arrival-rate",
      rate: HOT_RATE, timeUnit: "1s", duration: DUR,
      preAllocatedVUs: Math.max(200, Math.ceil(HOT_RATE / 10)), maxVUs: Math.max(1000, HOT_RATE),
      exec: "hot",
    },
    light: {
      executor: "constant-arrival-rate",
      rate: LIGHT_RATE, timeUnit: "1s", duration: DUR,
      preAllocatedVUs: Math.max(100, Math.ceil(LIGHT_RATE / 10)), maxVUs: Math.max(500, LIGHT_RATE),
      exec: "light",
    },
  },
};

function hit(key, ok, ko) {
  const res = http.get(`${BASE}/ratelimit/x`, { headers: { "x-plecto-ratelimit": key } });
  if (res.status === 200) ok.add(1);
  else if (res.status === 429) ko.add(1);
}

export function hot() { hit("tenant-hot", hotOk, hot429); }
export function light() { hit("tenant-light", lightOk, light429); }

export function handleSummary(data) {
  const secs = (data.state.testRunDurationMs || 1) / 1000;
  const c = (m) => (data.metrics[m] ? data.metrics[m].values.count : 0);
  const out = {
    duration_s: secs,
    hot_offered_rps: HOT_RATE,
    light_offered_rps: LIGHT_RATE,
    hot_ok: c("hot_ok"), hot_429: c("hot_429"),
    light_ok: c("light_ok"), light_429: c("light_429"),
    hot_allowed_rps: c("hot_ok") / secs,
    light_allowed_rps: c("light_ok") / secs,
    light_429_frac: c("light_429") / Math.max(1, c("light_ok") + c("light_429")),
  };
  const line =
    `\nfairness: HOT ${HOT_RATE}/s -> allowed ${out.hot_allowed_rps.toFixed(0)}/s (${out.hot_429} x429)  |  ` +
    `LIGHT ${LIGHT_RATE}/s -> allowed ${out.light_allowed_rps.toFixed(0)}/s (${out.light_429} x429, ` +
    `${(out.light_429_frac * 100).toFixed(2)}% shed)\n`;
  return { [OUT]: JSON.stringify(out, null, 2), stdout: line };
}
