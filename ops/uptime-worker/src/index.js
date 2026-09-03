// Uptime check for steepd. Runs on a 5-minute cron, fetches /healthz, and emails the
// operator via Resend ONLY when the state changes (down->up or up->down), so an outage
// is one message and recovery is one message, never a storm. State lives in KV.
//
// RESEND_API_KEY is a Worker secret (wrangler secret put RESEND_API_KEY), never in this
// file or in wrangler.toml.

export default {
  async scheduled(event, env, ctx) {
    let healthy = false;
    let low = false;
    let detail = "";
    try {
      const response = await fetch(env.HEALTH_URL, { signal: AbortSignal.timeout(10_000) });
      const body = await response.text();
      detail = `HTTP ${response.status} ${body.slice(0, 200)}`;
      healthy = response.ok && body.includes('"ok"');
      // /healthz adds "storage": "low" while the volume is under its warning threshold.
      low = healthy && body.includes('"low"');
    } catch (error) {
      detail = `fetch failed: ${error}`;
    }

    const previous = await env.STATE.get("health");
    const current = !healthy ? "down" : low ? "low" : "up";
    if (previous === current) return;
    await env.STATE.put("health", current);

    // First run with a healthy service is not news; a first run with a broken or nearly
    // full one is.
    if (previous === null && current === "up") return;

    const subjects = {
      down: "Steepd is down",
      low: "Steepd storage is low",
      up: previous === "down" ? "Steepd is back up" : "Steepd storage is fine again",
    };
    const subject = subjects[current];
    const text = `${subject}\n\n${env.HEALTH_URL}\n${detail}\nchecked ${new Date().toISOString()}`;
    if (!env.RESEND_API_KEY) {
      console.log("no RESEND_API_KEY secret set; state change not emailed:", subject);
      return;
    }
    const sent = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.RESEND_API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ from: env.ALERT_FROM, to: [env.ALERT_TO], subject, text }),
    });
    if (!sent.ok) console.log("alert email failed:", sent.status);
  },
};
