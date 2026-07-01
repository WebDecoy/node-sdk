/**
 * Category weights and automation UA patterns.
 *
 * Values match the FCaptcha standalone server (server.js), which is the most
 * complete variant of the engine and the one the reference test suite exercises.
 */

/**
 * Default per-category weights used to compute the final score.
 *
 * `stealth` carries deliberate anti-detection tampering (native functions
 * patched to hide automation). This is the least-ambiguous evidence of a bot —
 * a genuine browser never patches its own natives — so it is weighted highest.
 * Because weights are a simple weighted sum (not required to total 1.0), and
 * `stealth` is 0 for any clean browser, this raises stealth-bot scores without
 * affecting legitimate traffic.
 */
export const DEFAULT_WEIGHTS: Record<string, number> = {
  vision_ai: 0.15,
  headless: 0.15,
  automation: 0.08,
  cdp: 0.12,
  behavioral: 0.18,
  fingerprint: 0.08,
  rate_limit: 0.01,
  datacenter: 0.07,
  tor_vpn: 0.01,
  bot: 0.15,
  stealth: 0.3,
};

/** User-Agent substrings that indicate a known automation framework. */
export const AUTOMATION_UA_PATTERNS: RegExp[] = [
  /headless/i,
  /phantomjs/i,
  /selenium/i,
  /webdriver/i,
  /puppeteer/i,
  /playwright/i,
  /cypress/i,
  /nightwatch/i,
  /zombie/i,
  /electron/i,
  /chromium.*headless/i,
];
