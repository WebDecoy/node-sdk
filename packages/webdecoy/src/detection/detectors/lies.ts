/**
 * Native-function lie / tampering detection.
 *
 * Stealth automation (undetected-chromedriver, botasaurus, puppeteer-extra-
 * stealth) hides itself by overriding native functions — `navigator.webdriver`,
 * `Function.prototype.toString`, `navigator.permissions.query`,
 * `WebGLRenderingContext.getParameter`, etc. A patched native no longer reports
 * `[native code]` from `toString()`. A genuine browser never does this, so any
 * confirmed patch is high-confidence, deliberate evasion — the single strongest
 * "this is a stealth bot" signal, scored in its own `stealth` category.
 */

import type { Detection, LieDetectionInfo } from '../types';

export function analyzeLies(lie?: LieDetectionInfo): Detection[] {
  if (!lie || !lie.supported) return [];

  const patched = lie.patched ?? [];
  const count = lie.patchedCount ?? patched.length;
  if (count <= 0) return [];

  // One patch is already damning; each additional independent patch raises
  // certainty toward a ceiling.
  const score = Math.min(0.97, 0.7 + (count - 1) * 0.12);

  return [
    {
      category: 'stealth',
      score,
      confidence: 0.9,
      reason: `Native function(s) patched to hide automation: ${patched.join(', ') || `${count} function(s)`}`,
      details: { patched, patchedCount: count },
    },
  ];
}
