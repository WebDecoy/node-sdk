/**
 * Signal fixtures for the stealth-detection harness.
 *
 * IMPORTANT: these are *synthetic approximations* of what each client emits,
 * used for fast, deterministic regression measurement. They encode our current
 * model of botasaurus's output — they are NOT proof we catch the real tool.
 * Ground truth comes from the live harness (server.ts + page.html) with a real
 * botasaurus run. Treat fixture scores as "does the scoring logic fire on these
 * signal shapes", not "we catch botasaurus".
 */

import type { Signals } from '../src/detection/types';

/** A real Chrome-on-Windows User-Agent. */
export const CHROME_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

/** A real Chrome-on-Linux UA (botasaurus commonly runs on Linux servers). */
export const CHROME_LINUX_UA =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

/** Identical human-like behavioral block shared by the browser profiles so
 *  behavioral scoring is held constant and only environmental signals vary. */
const humanBehavioral = {
  totalPoints: 120,
  trajectoryLength: 3200,
  approachPoints: 40,
  velocityVariance: 0.8,
  straightLineRatio: 0.34,
  directionChanges: 42,
  eventDeltaVariance: 15,
  clickPrecision: 0.55,
  approachDirectness: 0.5,
  explorationRatio: 0.45,
  mouseEventRate: 28,
  interactionDuration: 8200,
  microTremorScore: 0.6,
  overshootCorrections: 3,
  keyEvents: 24,
  touchEvents: 0,
};

const humanTemporal = { pageLoadToFirstInteraction: 1300 };

/** Realistic headers a real browser sends. */
export const REAL_HEADERS: Record<string, string> = {
  accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'accept-language': 'en-US,en;q=0.9',
  'accept-encoding': 'gzip, deflate, br',
};

// ---------------------------------------------------------------------------
// Profile 1 — real Chrome (baseline; must score low / allow)
// ---------------------------------------------------------------------------
export const realChrome: Signals = {
  behavioral: humanBehavioral,
  temporal: humanTemporal,
  environmental: {
    webdriver: false,
    automationFlags: {
      plugins: 5,
      languages: true,
      chrome: true,
      chromeRuntime: true,
      platform: 'Win32',
      maxTouchPoints: 0,
      hardwareConcurrency: 8,
    },
    navigator: { platform: 'Win32', maxTouchPoints: 0 },
    webglInfo: {
      supported: true,
      vendor: 'Google Inc. (NVIDIA)',
      renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)',
      suspiciousRenderer: false,
    },
    audioInfo: { supported: true, sampleRate: 48000, state: 'suspended', baseLatency: 0.005333 },
    headlessIndicators: {
      hasOuterDimensions: true,
      innerEqualsOuter: false,
      notificationPermission: 'default',
    },
    cdp: { detected: false, signals: [] },
    playwright: { detected: false, signals: [] },
    workerConsistency: { supported: true, consistent: true, mismatchCount: 0, mismatches: [] },
    permissionsInfo: {
      supported: true,
      hasPermissionsAPI: true,
      hasClipboard: true,
      hasCredentials: true,
      hasGeolocation: true,
      hasUsb: true,
    },
    fontsInfo: { supported: true, count: 24, hasSegoeUI: true },
    canvasHash: { hash: '3f2a9c', supported: true },
    lieDetection: { supported: true, patched: [], patchedCount: 0 },
  },
};

// ---------------------------------------------------------------------------
// Profile 2a — botasaurus browser mode, CLOUD/headless (no GPU)
//   The catchable case: software WebGL + mocked audio + worker mismatch +
//   patched webdriver getter + patched native functions.
// ---------------------------------------------------------------------------
export const botasaurusBrowserCloud: Signals = {
  behavioral: humanBehavioral, // botasaurus does "humanized" movement — held constant
  temporal: humanTemporal,
  environmental: {
    webdriver: false, // stripped
    automationFlags: {
      plugins: 3,
      languages: true,
      chrome: true,
      chromeRuntime: false, // headless tell
      platform: 'Linux x86_64',
      maxTouchPoints: 0,
      hardwareConcurrency: 4,
    },
    navigator: { platform: 'Linux x86_64', maxTouchPoints: 0 },
    webglInfo: {
      supported: true,
      vendor: 'Google Inc.',
      renderer: 'Google SwiftShader',
      suspiciousRenderer: true,
    },
    audioInfo: { supported: true, sampleRate: 44100, state: 'suspended' /* baseLatency missing */ },
    headlessIndicators: {
      hasOuterDimensions: true,
      innerEqualsOuter: false,
      notificationPermission: 'default',
    },
    cdp: { detected: true, signals: ['webdriver_getter_modified'] },
    playwright: { detected: true, signals: ['webdriver_configurable'] },
    workerConsistency: {
      supported: true,
      consistent: false,
      mismatchCount: 2,
      mismatches: ['userAgent', 'hardwareConcurrency'],
    },
    permissionsInfo: { supported: true, hasPermissionsAPI: true, hasClipboard: true, hasGeolocation: true },
    fontsInfo: { supported: true, count: 8, hasSegoeUI: false },
    canvasHash: { hash: 'a91b02', supported: true },
    lieDetection: {
      supported: true,
      patched: ['Function.prototype.toString', 'navigator.permissions.query'],
      patchedCount: 2,
    },
  },
};

// ---------------------------------------------------------------------------
// Profile 2b — botasaurus browser mode, DESKTOP/headful (real GPU)
//   The HARD case: real WebGL + real audio + consistent workers. The ONLY
//   surviving tells are the patched webdriver getter and patched native
//   functions (lie detection). Shows why the lie detector matters.
// ---------------------------------------------------------------------------
export const botasaurusBrowserDesktop: Signals = {
  behavioral: humanBehavioral,
  temporal: humanTemporal,
  environmental: {
    webdriver: false,
    automationFlags: {
      plugins: 5,
      languages: true,
      chrome: true,
      chromeRuntime: true,
      platform: 'Win32',
      maxTouchPoints: 0,
      hardwareConcurrency: 8,
    },
    navigator: { platform: 'Win32', maxTouchPoints: 0 },
    webglInfo: {
      supported: true,
      vendor: 'Google Inc. (NVIDIA)',
      renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)',
      suspiciousRenderer: false,
    },
    audioInfo: { supported: true, sampleRate: 48000, state: 'suspended', baseLatency: 0.005333 },
    headlessIndicators: {
      hasOuterDimensions: true,
      innerEqualsOuter: false,
      notificationPermission: 'default',
    },
    // The stealth patches that survive even on real hardware:
    cdp: { detected: true, signals: ['webdriver_getter_modified'] },
    playwright: { detected: true, signals: ['webdriver_configurable'] },
    workerConsistency: { supported: true, consistent: true, mismatchCount: 0, mismatches: [] },
    permissionsInfo: { supported: true, hasPermissionsAPI: true, hasClipboard: true, hasGeolocation: true, hasUsb: true },
    fontsInfo: { supported: true, count: 22, hasSegoeUI: true },
    canvasHash: { hash: 'c40dd1', supported: true },
    lieDetection: {
      supported: true,
      patched: ['Function.prototype.toString', 'navigator.permissions.query', 'WebGLRenderingContext.getParameter'],
      patchedCount: 3,
    },
  },
};

// ---------------------------------------------------------------------------
// Profile 3 — botasaurus request mode (@request): no JS executed.
//   No environmental/behavioral signals at all. This is the F2 territory
//   (TLS + beacon-absence). Included to show what F1 alone does with it.
// ---------------------------------------------------------------------------
export const botasaurusRequest: Signals = {
  // No behavioral, no environmental — the collector never ran.
  meta: {},
};

export const PROFILES: Array<{ name: string; signals: Signals; ua: string; headers: Record<string, string> }> = [
  { name: 'real-chrome (baseline)', signals: realChrome, ua: CHROME_UA, headers: REAL_HEADERS },
  { name: 'botasaurus-browser-cloud', signals: botasaurusBrowserCloud, ua: CHROME_LINUX_UA, headers: REAL_HEADERS },
  { name: 'botasaurus-browser-desktop', signals: botasaurusBrowserDesktop, ua: CHROME_UA, headers: REAL_HEADERS },
  // request mode ships browser-like headers too; only accept-language sometimes differs.
  { name: 'botasaurus-request (no JS)', signals: botasaurusRequest, ua: CHROME_UA, headers: REAL_HEADERS },
];
