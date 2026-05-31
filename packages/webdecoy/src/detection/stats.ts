/**
 * Statistical utilities for keystroke-cadence analysis.
 *
 * Ported verbatim from FCaptcha detection.js so cadence scores match exactly.
 */

export function mean(arr: number[]): number {
  if (arr.length === 0) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

export function stddev(arr: number[]): number {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  const variance = arr.reduce((acc, v) => acc + (v - m) * (v - m), 0) / arr.length;
  return Math.sqrt(variance);
}

/** Abramowitz & Stegun error-function approximation (max error ~1.5e-7). */
export function erf(x: number): number {
  const sign = x >= 0 ? 1 : -1;
  x = Math.abs(x);
  const t = 1.0 / (1.0 + 0.3275911 * x);
  const y =
    1.0 -
    (((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t + 0.254829592) *
      t *
      Math.exp(-x * x));
  return sign * y;
}

export function normalCDF(x: number, mu: number, sigma: number): number {
  if (sigma <= 0) return x >= mu ? 1.0 : 0.0;
  return 0.5 * (1.0 + erf((x - mu) / (sigma * Math.SQRT2)));
}

/** One-sample Kolmogorov-Smirnov statistic against `cdfFn`. */
export function ksTestStatistic(samples: number[], cdfFn: (x: number) => number): number {
  const n = samples.length;
  if (n === 0) return 0;
  const sorted = [...samples].sort((a, b) => a - b);
  let maxD = 0;
  for (let i = 0; i < n; i++) {
    const empirical = (i + 1) / n;
    const theoretical = cdfFn(sorted[i]);
    const d1 = Math.abs(empirical - theoretical);
    const d2 = Math.abs(i / n - theoretical);
    maxD = Math.max(maxD, d1, d2);
  }
  return maxD;
}

/** Shannon entropy (bits) of `arr` binned into `bins` equal-width buckets. */
export function shannonEntropy(arr: number[], bins: number): number {
  if (arr.length === 0) return 0;
  const min = Math.min(...arr);
  const max = Math.max(...arr);
  if (max === min) return 0;
  const binWidth = (max - min) / bins;
  const counts = new Array(bins).fill(0);
  for (const v of arr) {
    let idx = Math.floor((v - min) / binWidth);
    if (idx >= bins) idx = bins - 1;
    counts[idx]++;
  }
  const n = arr.length;
  let entropy = 0;
  for (const c of counts) {
    if (c > 0) {
      const p = c / n;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

/** Lag-1 autocorrelation coefficient of `arr`. */
export function lag1Autocorrelation(arr: number[]): number {
  if (arr.length < 3) return 0;
  const n = arr.length - 1;
  const x = arr.slice(0, n);
  const y = arr.slice(1);
  const mx = mean(x);
  const my = mean(y);
  let num = 0;
  let dx2 = 0;
  let dy2 = 0;
  for (let i = 0; i < n; i++) {
    const dx = x[i] - mx;
    const dy = y[i] - my;
    num += dx * dy;
    dx2 += dx * dx;
    dy2 += dy * dy;
  }
  const denom = Math.sqrt(dx2 * dy2);
  if (denom === 0) return 0;
  return num / denom;
}
