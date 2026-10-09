import { execFileSync } from "node:child_process";

/**
 * Reset rate-limit counters so repeated local runs don't trip the (real, unmodified)
 * limits. Done from outside the app on purpose: there is no test-only bypass in the API.
 */
export default function globalSetup() {
  const script = "redis-cli --scan --pattern 'rl:*' | xargs -r redis-cli del > /dev/null";
  execFileSync("docker", ["compose", "exec", "-T", "redis", "sh", "-c", script], {
    cwd: "../..",
    stdio: "inherit",
  });
}
