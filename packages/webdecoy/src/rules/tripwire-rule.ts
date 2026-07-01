/**
 * Tripwire Rule (F4 — deception layer)
 *
 * Deterministic, zero-false-positive bot detection: a request for a hidden
 * honeypot path (a "tripwire") that a real user can never reach — because it is
 * only exposed as an invisible link, listed in robots.txt `Disallow`, or is a
 * scanner-bait path no human ever types — is, by construction, automated.
 *
 * Unlike fingerprinting (which a stealth tool like botasaurus is purpose-built
 * to defeat), a tripwire detects *intent* — going where a human cannot — which
 * cannot be spoofed away by a better browser fingerprint.
 *
 * Implemented as a {@link Rule} so it flows through the existing
 * DENY -> block -> violation-report pipeline with no middleware changes.
 */

import type { Rule, RuleContext, RuleResult, TripwireConfig } from './types';

/**
 * Common scanner/scraper bait paths that no legitimate user ever requests.
 * Requesting any of these is a strong automated-intent signal on its own.
 */
export const DEFAULT_TRIPWIRE_PATHS: readonly string[] = [
  '/.git/config',
  '/.git/HEAD',
  '/.env',
  '/.env.local',
  '/.env.production',
  '/wp-config.php',
  '/config.php',
  '/.aws/credentials',
  '/.ssh/id_rsa',
  '/backup.zip',
  '/backup.sql',
  '/database.sql',
  '/dump.sql',
  '/.DS_Store',
  '/phpinfo.php',
  '/server-status',
  '/actuator/env',
  '/.vscode/sftp.json',
];

/** Strip query string and fragment for path matching. */
function normalizePath(path: string): string {
  return path.split('?')[0].split('#')[0];
}

export class TripwireRule implements Rule {
  readonly name = 'tripwire';
  private readonly exact: Set<string>;
  private readonly prefixes: string[];
  private readonly patterns: RegExp[];
  private readonly action: 'DENY' | 'THROTTLE';
  private readonly dryRun: boolean;

  constructor(config: TripwireConfig = {}) {
    const paths = [...(config.paths ?? [])];
    if (config.includeDefaults ?? true) paths.push(...DEFAULT_TRIPWIRE_PATHS);
    this.exact = new Set(paths);
    this.prefixes = config.prefixes ?? [];
    this.patterns = config.patterns ?? [];
    this.action = config.action ?? 'DENY';
    this.dryRun = config.dryRun ?? false;
  }

  evaluate(context: RuleContext): RuleResult {
    const path = normalizePath(context.path);
    const hit =
      this.exact.has(path) ||
      this.prefixes.some((prefix) => path.startsWith(prefix)) ||
      this.patterns.some((re) => re.test(path));

    if (hit) {
      return {
        action: this.dryRun ? 'ALLOW' : this.action,
        rule: this.name,
        reason: `Tripwire hit: ${path} — hidden honeypot path, deterministic automated-intent signal`,
        metadata: { path, dryRun: this.dryRun, confidence: 100 },
      };
    }

    return { action: 'ALLOW', rule: this.name };
  }
}
