/** Generic automation timing detection (JS speed, RAF, mouse event cadence). */

import type { Detection, Signals } from '../types';

export function detectAutomation(signals: Signals): Detection[] {
  const detections: Detection[] = [];
  const env = signals.environmental ?? {};
  const b = signals.behavioral ?? {};

  const jsTime = env.jsExecutionTime?.mathOps ?? 0;
  if (jsTime > 0) {
    if (jsTime < 0.1) {
      detections.push({
        category: 'automation',
        score: 0.4,
        confidence: 0.3,
        reason: 'JS execution unusually fast',
      });
    } else if (jsTime > 50) {
      detections.push({
        category: 'automation',
        score: 0.3,
        confidence: 0.3,
        reason: 'JS execution unusually slow',
      });
    }
  }

  const raf = env.rafConsistency ?? {};
  if (raf.frameTimeVariance !== undefined && raf.frameTimeVariance < 0.1) {
    detections.push({
      category: 'automation',
      score: 0.5,
      confidence: 0.4,
      reason: 'RequestAnimationFrame timing too consistent',
    });
  }

  const eventVar = b.eventDeltaVariance ?? 10;
  const totalPoints = b.totalPoints ?? 0;
  if (eventVar < 2 && totalPoints > 10) {
    detections.push({
      category: 'automation',
      score: 0.6,
      confidence: 0.6,
      reason: 'Mouse event timing unnaturally consistent',
    });
  }

  return detections;
}
