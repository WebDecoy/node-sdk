/** HTTP header analysis: missing browser headers, proxy headers, Accept-*. */

import type { Detection } from '../types';

const SUSPICIOUS_HEADERS = new Set([
  'x-requested-with', 'x-forwarded-for', 'x-real-ip', 'via',
  'forwarded', 'x-originating-ip', 'cf-connecting-ip',
  'true-client-ip', 'x-cluster-client-ip',
]);

const EXPECTED_BROWSER_HEADERS = ['accept', 'accept-language', 'accept-encoding', 'user-agent'];

export function analyzeHeaders(headers: Record<string, string>): Detection[] {
  const detections: Detection[] = [];
  const headersLower: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    headersLower[key.toLowerCase()] = value;
  }

  let missingCount = 0;
  for (const header of EXPECTED_BROWSER_HEADERS) {
    if (!(header in headersLower)) missingCount++;
  }
  if (missingCount > 1) {
    detections.push({
      category: 'bot',
      score: 0.4,
      confidence: 0.5,
      reason: `Missing ${missingCount} expected browser headers`,
    });
  }

  for (const header of Object.keys(headersLower)) {
    if (SUSPICIOUS_HEADERS.has(header)) {
      detections.push({
        category: 'bot',
        score: 0.3,
        confidence: 0.4,
        reason: `Suspicious header present: ${header}`,
      });
    }
  }

  const acceptLang = headersLower['accept-language'] ?? '';
  if (acceptLang === '' || acceptLang === '*') {
    detections.push({
      category: 'bot',
      score: 0.3,
      confidence: 0.4,
      reason: 'Invalid Accept-Language header',
    });
  }

  const acceptEnc = headersLower['accept-encoding'] ?? '';
  if (acceptEnc && !acceptEnc.includes('gzip') && !acceptEnc.includes('deflate')) {
    detections.push({
      category: 'bot',
      score: 0.2,
      confidence: 0.3,
      reason: 'Unusual Accept-Encoding',
    });
  }

  return detections;
}
