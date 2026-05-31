/**
 * Keystroke-cadence analysis.
 *
 * Combines seven weighted metrics (dwell variance, log-normal fit, uniformity,
 * lag-1 autocorrelation, burst regularity, Shannon entropy, rollover rate) into
 * a human-likeness score; emits a detection when the inverted (bot) score
 * exceeds 0.55. Ported verbatim from FCaptcha detection.js.
 */

import type { Detection, TextareaKeyboardStats } from '../types';
import { mean, stddev, ksTestStatistic, normalCDF, shannonEntropy, lag1Autocorrelation } from '../stats';

export function analyzeKeystrokeCadence(stats: TextareaKeyboardStats): Detection | null {
  const keyCount = stats.keyCount ?? 0;
  const intervals = stats.intervals ?? [];
  const dwellTimes = stats.dwellTimes ?? [];
  const rollovers = stats.rollovers ?? 0;

  // Gate on minimum data.
  if (keyCount < 20 || intervals.length < 15) return null;

  const metrics: Record<string, number> = {};
  let totalWeight = 0;
  let weightedSum = 0;
  let activeMetricCount = 0;

  // 1. Dwell Variance (weight 0.15)
  if (dwellTimes.length >= 10) {
    const dSd = stddev(dwellTimes);
    let score: number;
    if (dSd < 3) score = 0;
    else if (dSd < 10) score = (0.35 * (dSd - 3)) / 7;
    else if (dSd < 20) score = 0.35 + (0.65 * (dSd - 10)) / 10;
    else score = 1.0;
    metrics.dwellVariance = score;
    totalWeight += 0.15;
    weightedSum += score * 0.15;
    activeMetricCount++;
  }

  // 2. Log-Normal Fit (weight 0.20)
  if (intervals.length >= 15) {
    const logIntervals = intervals.filter((v) => v > 0).map((v) => Math.log(v));
    if (logIntervals.length >= 10) {
      const mu = mean(logIntervals);
      const sigma = stddev(logIntervals);
      const D = ksTestStatistic(logIntervals, (x) => normalCDF(x, mu, sigma));
      const critical = 1.22 / Math.sqrt(logIntervals.length);
      let score: number;
      if (D <= critical * 0.8) score = 1.0;
      else if (D <= critical) score = 0.7;
      else if (D <= critical * 1.5) score = 0.3;
      else score = 0;
      metrics.logNormalFit = score;
      totalWeight += 0.2;
      weightedSum += score * 0.2;
      activeMetricCount++;
    }
  }

  // 3. Uniformity Detection (weight 0.15)
  if (intervals.length >= 15) {
    const minI = Math.min(...intervals);
    const maxI = Math.max(...intervals);
    if (maxI > minI) {
      const D = ksTestStatistic(intervals, (x) => (x - minI) / (maxI - minI));
      let score: number;
      if (D < 0.05) score = 0;
      else if (D < 0.1) score = 0.3;
      else if (D < 0.15) score = 0.6;
      else score = 1.0;
      metrics.uniformity = score;
      totalWeight += 0.15;
      weightedSum += score * 0.15;
      activeMetricCount++;
    }
  }

  // 4. Lag-1 Autocorrelation (weight 0.15)
  if (intervals.length >= 15) {
    const r = Math.abs(lag1Autocorrelation(intervals));
    let score: number;
    if (r < 0.02) score = 0.1;
    else if (r < 0.1) score = 0.1 + (0.4 * (r - 0.02)) / 0.08;
    else if (r < 0.2) score = 0.5 + (0.4 * (r - 0.1)) / 0.1;
    else if (r <= 0.4) score = 0.9;
    else if (r <= 0.6) score = 0.9 - (0.4 * (r - 0.4)) / 0.2;
    else score = 0.5;
    metrics.autocorrelation = score;
    totalWeight += 0.15;
    weightedSum += score * 0.15;
    activeMetricCount++;
  }

  // 5. Burst Regularity (weight 0.10)
  const burstGaps: number[] = [];
  for (let i = 0; i < intervals.length; i++) {
    if (intervals[i] > 300) burstGaps.push(intervals[i]);
  }
  if (burstGaps.length >= 3) {
    const burstMean = mean(burstGaps);
    const burstSd = stddev(burstGaps);
    const cv = burstMean > 0 ? burstSd / burstMean : 0;
    let score: number;
    if (cv < 0.1) score = 0.1;
    else if (cv < 0.3) score = 0.1 + (0.9 * (cv - 0.1)) / 0.2;
    else score = 1.0;
    metrics.burstRegularity = score;
    totalWeight += 0.1;
    weightedSum += score * 0.1;
    activeMetricCount++;
  }

  // 6. Shannon Entropy (weight 0.15)
  if (intervals.length >= 15) {
    const H = shannonEntropy(intervals, 10);
    let score: number;
    if (H < 0.5) score = 0.1;
    else if (H < 1.5) score = 0.1 + 0.5 * (H - 0.5);
    else if (H < 2.0) score = 0.6 + (0.4 * (H - 1.5)) / 0.5;
    else if (H <= 3.0) score = 1.0;
    else if (H <= 3.3) score = 0.7;
    else score = 0.4;
    metrics.entropy = score;
    totalWeight += 0.15;
    weightedSum += score * 0.15;
    activeMetricCount++;
  }

  // 7. Rollover Rate (weight 0.10)
  if (keyCount >= 30) {
    const rate = rollovers / keyCount;
    let score: number;
    if (rate === 0) score = 0.5;
    else if (rate < 0.05) score = 0.5 + 0.3 * (rate / 0.05);
    else if (rate < 0.15) score = 0.8 + 0.2 * ((rate - 0.05) / 0.1);
    else score = 1.0;
    metrics.rolloverRate = score;
    totalWeight += 0.1;
    weightedSum += score * 0.1;
    activeMetricCount++;
  }

  if (totalWeight === 0) return null;

  const humanScore = weightedSum / totalWeight;
  const botScore = 1.0 - humanScore;

  if (botScore <= 0.55) return null;

  return {
    category: 'bot',
    score: botScore * 0.7,
    confidence: Math.min(0.7, activeMetricCount / 7),
    reason: 'Keystroke cadence analysis indicates non-human typing pattern',
    details: { metrics, cadenceHumanScore: humanScore },
  };
}
