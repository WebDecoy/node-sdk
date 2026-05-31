/** Headless-browser detection: WebDriver, automation flags, UA, Playwright. */

import type { Detection, Signals } from '../types';
import { AUTOMATION_UA_PATTERNS } from '../weights';

const PLAYWRIGHT_SCORE_MAP: Record<string, number> = {
  playwright_globals: 0.95,
  webdriver_deleted: 0.8,
  webdriver_configurable: 0.7,
  chrome_runtime_missing: 0.6,
};

export function detectHeadless(signals: Signals, userAgent: string): Detection[] {
  const detections: Detection[] = [];
  const env = signals.environmental ?? {};
  const headless = env.headlessIndicators ?? {};
  const automation = env.automationFlags ?? {};

  if (env.webdriver) {
    detections.push({
      category: 'headless',
      score: 0.95,
      confidence: 0.95,
      reason: 'WebDriver detected',
    });
  }

  if (automation.plugins === 0) {
    detections.push({
      category: 'headless',
      score: 0.6,
      confidence: 0.6,
      reason: 'No browser plugins detected',
    });
  }

  if (automation.languages === false) {
    detections.push({
      category: 'headless',
      score: 0.5,
      confidence: 0.5,
      reason: 'No navigator.languages',
    });
  }

  if (headless.hasOuterDimensions === false) {
    detections.push({
      category: 'headless',
      score: 0.7,
      confidence: 0.7,
      reason: 'Window lacks outer dimensions',
    });
  }

  if (headless.innerEqualsOuter === true) {
    detections.push({
      category: 'headless',
      score: 0.4,
      confidence: 0.5,
      reason: 'Viewport equals window size',
    });
  }

  if (headless.notificationPermission === 'denied') {
    detections.push({
      category: 'headless',
      score: 0.3,
      confidence: 0.4,
      reason: 'Notifications pre-denied',
    });
  }

  for (const pattern of AUTOMATION_UA_PATTERNS) {
    if (pattern.test(userAgent)) {
      detections.push({
        category: 'headless',
        score: 0.9,
        confidence: 0.9,
        reason: 'Automation pattern in User-Agent',
      });
      break;
    }
  }

  const renderer = (env.webglInfo?.renderer ?? '').toLowerCase();
  if (renderer.includes('swiftshader') || renderer.includes('llvmpipe')) {
    detections.push({
      category: 'headless',
      score: 0.8,
      confidence: 0.8,
      reason: 'Software WebGL renderer detected',
    });
  }

  const playwright = env.playwright ?? {};
  if (playwright.detected) {
    for (const sig of playwright.signals ?? []) {
      detections.push({
        category: 'headless',
        score: PLAYWRIGHT_SCORE_MAP[sig] ?? 0.7,
        confidence: 0.8,
        reason: `Playwright artifact detected: ${sig}`,
      });
    }
  }

  return detections;
}
