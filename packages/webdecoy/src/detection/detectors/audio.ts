/** AudioContext fingerprint analysis: headless/mocked audio-stack detection. */

import type { AudioContextInfo, Detection } from '../types';

export function analyzeAudioContext(audioInfo?: AudioContextInfo): Detection[] {
  if (!audioInfo) return [];
  const detections: Detection[] = [];

  // No AudioContext at all — common in headless/sandboxed browsers.
  if (audioInfo.supported === false) {
    detections.push({
      category: 'headless',
      score: 0.6,
      confidence: 0.6,
      reason: 'AudioContext unavailable (headless or blocked audio stack)',
    });
    return detections;
  }

  // Real browsers expose `baseLatency`; stealth tools that stub AudioContext
  // routinely omit it.
  if (audioInfo.baseLatency === undefined || audioInfo.baseLatency === null) {
    detections.push({
      category: 'headless',
      score: 0.55,
      confidence: 0.6,
      reason: 'AudioContext missing baseLatency (mocked/headless audio)',
    });
  }

  // Conventional sample rates are 44100 or 48000. Anything else is unusual for
  // a genuine consumer device.
  const sr = audioInfo.sampleRate;
  if (sr !== undefined && sr !== 44100 && sr !== 48000) {
    detections.push({
      category: 'headless',
      score: 0.4,
      confidence: 0.5,
      reason: `Unusual AudioContext sample rate (${sr})`,
    });
  }

  return detections;
}
