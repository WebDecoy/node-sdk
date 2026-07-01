/**
 * Stealth-detection measurement harness.
 *
 * Runs each signal profile in `fixtures.ts` through the REAL DetectionEngine
 * and prints score, recommendation, and every triggered detection. Use it to
 * establish a baseline before changes and to measure the delta after.
 *
 *   npx tsx harness/measure.ts
 *
 * `requirePoW` is disabled so we score raw signals (the PoW hard-fail would
 * otherwise dominate and mask the fingerprint signal we're measuring).
 */

import { DetectionEngine } from '../src/detection/engine';
import type { Detection } from '../src/detection/types';
import { PROFILES } from './fixtures';

const engine = new DetectionEngine({ requirePoW: false });

function fmtPct(n: number): string {
  return (n * 100).toFixed(0).padStart(3) + '%';
}

function recBadge(rec: string): string {
  if (rec === 'block') return 'BLOCK';
  if (rec === 'challenge') return 'CHALLENGE';
  return 'allow';
}

const summary: Array<{ name: string; score: number; rec: string; hits: number }> = [];

for (const profile of PROFILES) {
  // A controlled, non-datacenter IP so IP reputation doesn't confound the run.
  const verdict = engine.score(profile.signals, {
    ip: '203.0.113.10',
    siteKey: 'harness',
    userAgent: profile.ua,
    headers: profile.headers,
  });

  const triggered = verdict.detections.filter((d: Detection) => d.score > 0);
  triggered.sort((a, b) => b.score * b.confidence - a.score * a.confidence);

  console.log('\n' + '='.repeat(78));
  console.log(`PROFILE: ${profile.name}`);
  console.log(
    `  score=${fmtPct(verdict.score)}  ->  ${recBadge(verdict.recommendation)}   (block>=60%, challenge>=30%)`,
  );
  console.log('  triggered detections:');
  if (triggered.length === 0) {
    console.log('    (none)');
  }
  for (const d of triggered) {
    console.log(
      `    [${d.category.padEnd(12)}] score=${fmtPct(d.score)} conf=${fmtPct(d.confidence)}  ${d.reason}`,
    );
  }

  summary.push({ name: profile.name, score: verdict.score, rec: verdict.recommendation, hits: triggered.length });
}

console.log('\n' + '='.repeat(78));
console.log('SUMMARY');
console.log('  ' + 'profile'.padEnd(32) + 'score   verdict     detections');
for (const s of summary) {
  console.log(
    '  ' + s.name.padEnd(32) + fmtPct(s.score) + '    ' + recBadge(s.rec).padEnd(11) + ' ' + s.hits,
  );
}
console.log('');
