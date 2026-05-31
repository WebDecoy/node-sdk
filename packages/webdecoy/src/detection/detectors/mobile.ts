/**
 * Mobile-native detectors: touch authenticity, sensor entropy, touch kinematics.
 *
 * UA-gated on mobile; non-mobile UAs are a no-op. Designed never to penalize iOS
 * Safari without sensor permission (absence of motion events is treated as
 * neutral). Ported from FCaptcha server.js.
 */

import type { Detection, Signals } from '../types';
import { isMobileUA } from '../ua';

export function detectTouchAuthenticity(signals: Signals, userAgent: string): Detection[] {
  const detections: Detection[] = [];
  if (!isMobileUA(userAgent)) return detections;

  const b = signals.behavioral ?? {};
  const touchPoints = b.touchTotalPoints ?? b.touchEvents ?? 0;
  if (touchPoints < 3) return detections;

  const forceVariance = b.touchForceVariance ?? 0;
  const radiusVariance = b.touchRadiusVariance ?? 0;
  const forceAllOne = b.touchForceAllOne === true;
  const uniqueIds = b.touchUniqueIdentifiers ?? 0;
  const forceMax = b.touchForceMax ?? 0;
  const radiusMax = b.touchRadiusMax ?? 0;

  // Uniform non-zero force across all events → synthetic injection. Older Android
  // returning all-zero is legitimate — only penalize uniformity when max > 0.
  if (forceVariance === 0 && forceMax > 0 && touchPoints >= 5) {
    detections.push({
      category: 'behavioral',
      score: 0.75,
      confidence: 0.85,
      reason: 'Touch force is identical across all events (synthetic touch)',
    });
  }

  // All force=1 exactly is a common synthetic default in automation frameworks.
  if (forceAllOne && touchPoints >= 5) {
    detections.push({
      category: 'behavioral',
      score: 0.8,
      confidence: 0.9,
      reason: 'All touches report force=1.0 exactly (synthetic pattern)',
    });
  }

  // Uniform contact radius across many events is unusual on real phones.
  if (radiusVariance === 0 && radiusMax > 0 && touchPoints >= 5) {
    detections.push({
      category: 'behavioral',
      score: 0.7,
      confidence: 0.8,
      reason: 'Touch contact radius identical across all events',
    });
  }

  // Mobile UA with real touches but zero unique identifiers — framework default.
  if (touchPoints >= 5 && uniqueIds === 0) {
    detections.push({
      category: 'behavioral',
      score: 0.6,
      confidence: 0.7,
      reason: 'Mobile touches lack identifier tracking (synthetic injection)',
    });
  }

  return detections;
}

export function detectSensorEntropy(signals: Signals, userAgent: string): Detection[] {
  const detections: Detection[] = [];
  if (!isMobileUA(userAgent)) return detections;

  const sensor = signals.environmental?.sensor ?? {};
  const motionCount = sensor.motionEventCount ?? 0;
  const motionVariance = sensor.motionAccelVariance ?? 0;
  const orientationCount = sensor.orientationEventCount ?? 0;
  const orientationVariance = sensor.orientationVariance ?? 0;

  // Sensor events fired but completely flat → emulator / headless mobile.
  if (motionCount >= 10 && motionVariance < 0.01) {
    detections.push({
      category: 'headless',
      score: 0.7,
      confidence: 0.8,
      reason: `Motion sensor active but flat (variance=${motionVariance.toFixed(4)}) — likely emulator`,
    });
  }

  if (orientationCount >= 10 && orientationVariance < 0.01) {
    detections.push({
      category: 'headless',
      score: 0.6,
      confidence: 0.7,
      reason: 'Orientation sensor active but completely flat — likely emulator',
    });
  }

  // motionCount === 0 is NEUTRAL (iOS without permission is the common case).

  return detections;
}

export function detectTouchKinematics(signals: Signals): Detection[] {
  const detections: Detection[] = [];
  const b = signals.behavioral ?? {};
  const touchPoints = b.touchTotalPoints ?? 0;
  if (touchPoints < 10) return detections;

  const straightLine = b.touchStraightLineRatio ?? 0;
  const tremor = b.touchMicroTremorScore ?? 0;
  const dirChanges = b.touchDirectionChanges ?? 0;

  if (straightLine > 0.85 && touchPoints >= 20) {
    detections.push({
      category: 'behavioral',
      score: 0.65,
      confidence: 0.75,
      reason: `Touch path too straight (ratio=${straightLine.toFixed(2)}) — automation pattern`,
    });
  }

  if (tremor < 0.05 && touchPoints >= 30) {
    detections.push({
      category: 'behavioral',
      score: 0.55,
      confidence: 0.65,
      reason: 'Touch path has no micro-tremor (unnaturally smooth)',
    });
  }

  if (dirChanges === 0 && touchPoints >= 30) {
    detections.push({
      category: 'behavioral',
      score: 0.5,
      confidence: 0.6,
      reason: 'Touch path has zero direction changes over long trajectory',
    });
  }

  return detections;
}
