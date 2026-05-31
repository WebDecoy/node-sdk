/**
 * Category weights and automation UA patterns.
 *
 * Values match the FCaptcha standalone server (server.js), which is the most
 * complete variant of the engine and the one the reference test suite exercises.
 */

/** Default per-category weights used to compute the final score. */
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
