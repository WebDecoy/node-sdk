/** Per-IP rate-abuse detection. */

import type { Detection } from '../types';
import type { RateLimiter } from '../stores';

export function detectRateAbuse(ip: string, siteKey: string, limiter: RateLimiter): Detection[] {
  const detections: Detection[] = [];
  const [exceeded, count] = limiter.check(`${siteKey}:${ip}`, 60, 10);

  if (exceeded) {
    detections.push({
      category: 'rate_limit',
      score: 0.8,
      confidence: 0.9,
      reason: 'Rate limit exceeded',
    });
  } else if (count > 5) {
    detections.push({
      category: 'rate_limit',
      score: 0.3,
      confidence: 0.5,
      reason: 'High request rate',
    });
  }

  return detections;
}
