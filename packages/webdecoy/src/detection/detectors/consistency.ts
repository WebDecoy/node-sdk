/** Browser consistency: UA vs. platform/touch/window.chrome, bot UAs. */

import type { Detection, Signals } from '../types';
import { parseUserAgent } from '../ua';

export function checkBrowserConsistency(ua: string, signals: Signals): Detection[] {
  const detections: Detection[] = [];
  const uaInfo = parseUserAgent(ua);

  if (uaInfo.isBot) {
    detections.push({
      category: 'bot',
      score: 0.9,
      confidence: 0.95,
      reason: `User-Agent indicates bot: ${uaInfo.botName}`,
    });
    return detections;
  }

  const env = signals.environmental ?? {};
  const nav = env.navigator ?? {};
  const automation = env.automationFlags ?? {};
  const platform = nav.platform ?? automation.platform ?? '';

  if (uaInfo.os === 'Windows' && !platform.includes('Win')) {
    detections.push({
      category: 'bot',
      score: 0.6,
      confidence: 0.7,
      reason: `UA/platform mismatch: UA claims Windows, platform=${platform}`,
    });
  }

  if (uaInfo.os === 'macOS' && !platform.includes('Mac')) {
    detections.push({
      category: 'bot',
      score: 0.6,
      confidence: 0.7,
      reason: `UA/platform mismatch: UA claims macOS, platform=${platform}`,
    });
  }

  if (uaInfo.os === 'Linux' && !platform.includes('Linux')) {
    detections.push({
      category: 'bot',
      score: 0.6,
      confidence: 0.7,
      reason: `UA/platform mismatch: UA claims Linux, platform=${platform}`,
    });
  }

  const maxTouch = nav.maxTouchPoints ?? automation.maxTouchPoints ?? 0;
  if (uaInfo.isMobile && maxTouch === 0) {
    detections.push({
      category: 'bot',
      score: 0.5,
      confidence: 0.6,
      reason: 'UA claims mobile but no touch support',
    });
  }

  if (uaInfo.browser === 'Chrome' && !automation.chrome) {
    detections.push({
      category: 'bot',
      score: 0.7,
      confidence: 0.8,
      reason: 'UA claims Chrome but window.chrome missing',
    });
  }

  return detections;
}
