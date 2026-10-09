import { resetRateLimits } from "./fixtures";

/** Start the run from clean rate-limit counters (see `resetRateLimits`). */
export default function globalSetup() {
  resetRateLimits();
}
