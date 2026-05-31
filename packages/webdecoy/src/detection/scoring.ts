/** Score aggregation: per-category confidence-weighted means → weighted total. */

import type { CategoryScores, Detection, Recommendation } from './types';

/**
 * Aggregate detections into per-category scores. Each category's score is the
 * confidence-weighted mean of its detections' scores, capped at 1.0. Categories
 * present in `weights` but with no detections are filled with 0.
 */
export function calculateCategoryScores(
  detections: Detection[],
  weights: Record<string, number>,
): CategoryScores {
  const categoryData: Record<string, Array<[number, number]>> = {};

  for (const d of detections) {
    (categoryData[d.category] ??= []).push([d.score, d.confidence]);
  }

  const result: CategoryScores = {};
  for (const [cat, scores] of Object.entries(categoryData)) {
    if (scores.length > 0) {
      const totalWeight = scores.reduce((sum, [, conf]) => sum + conf, 0);
      if (totalWeight > 0) {
        const weightedSum = scores.reduce((sum, [score, conf]) => sum + score * conf, 0);
        result[cat] = Math.min(1.0, weightedSum / totalWeight);
      }
    }
  }

  for (const cat of Object.keys(weights)) {
    if (!(cat in result)) result[cat] = 0.0;
  }

  return result;
}

/** Combine category scores into the final weighted score (capped at 1.0). */
export function calculateFinalScore(
  categoryScores: CategoryScores,
  weights: Record<string, number>,
): number {
  let total = 0;
  for (const [cat, weight] of Object.entries(weights)) {
    total += (categoryScores[cat] ?? 0) * weight;
  }
  return Math.min(1.0, total);
}

/** Map a final score to an action recommendation. */
export function recommend(finalScore: number): Recommendation {
  if (finalScore < 0.3) return 'allow';
  if (finalScore < 0.6) return 'challenge';
  return 'block';
}
