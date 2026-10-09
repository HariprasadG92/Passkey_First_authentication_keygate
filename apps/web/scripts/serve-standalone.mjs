// Serve the `output: "standalone"` build exactly as the production image does.
// Next leaves static assets out of the standalone folder; copy them in first.
import { cpSync, existsSync } from "node:fs";

const out = ".next/standalone";
if (!existsSync(`${out}/server.js`)) {
  console.error("No standalone build found. Run `pnpm build` first.");
  process.exit(1);
}
cpSync(".next/static", `${out}/.next/static`, { recursive: true });
cpSync("public", `${out}/public`, { recursive: true });

process.chdir(out);
await import(`${process.cwd()}/server.js`);
