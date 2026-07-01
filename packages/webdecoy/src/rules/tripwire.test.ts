import { TripwireRule, tripwire, honeytoken, DEFAULT_TRIPWIRE_PATHS, RuleEngine } from './index';
import type { RuleContext } from './types';

function ctx(path: string): RuleContext {
  return { ip: '203.0.113.10', path, method: 'GET', headers: {}, timestamp: 1_700_000_000_000 };
}

describe('TripwireRule', () => {
  it('DENYs built-in scanner-bait paths', () => {
    const rule = new TripwireRule();
    for (const p of ['/.env', '/.git/config', '/wp-config.php']) {
      expect(rule.evaluate(ctx(p)).action).toBe('DENY');
    }
    // sanity: the defaults list is actually populated
    expect(DEFAULT_TRIPWIRE_PATHS.length).toBeGreaterThan(5);
  });

  it('ALLOWs normal application paths', () => {
    const rule = new TripwireRule();
    for (const p of ['/', '/products', '/api/users', '/about']) {
      expect(rule.evaluate(ctx(p)).action).toBe('ALLOW');
    }
  });

  it('DENYs a registered honeytoken path and reports confidence 100', () => {
    const rule = new TripwireRule({ paths: ['/__wd/abc123'] });
    const res = rule.evaluate(ctx('/__wd/abc123'));
    expect(res.action).toBe('DENY');
    expect(res.metadata?.confidence).toBe(100);
    expect(res.reason).toMatch(/Tripwire hit/);
  });

  it('strips query string and fragment before matching', () => {
    const rule = new TripwireRule();
    expect(rule.evaluate(ctx('/.env?foo=bar')).action).toBe('DENY');
    expect(rule.evaluate(ctx('/.git/config#x')).action).toBe('DENY');
  });

  it('respects includeDefaults: false', () => {
    const rule = new TripwireRule({ paths: ['/trap'], includeDefaults: false });
    expect(rule.evaluate(ctx('/.env')).action).toBe('ALLOW');
    expect(rule.evaluate(ctx('/trap')).action).toBe('DENY');
  });

  it('supports prefixes and patterns', () => {
    const rule = new TripwireRule({ prefixes: ['/.git/'], patterns: [/\/admin-backup/], includeDefaults: false });
    expect(rule.evaluate(ctx('/.git/anything/deep')).action).toBe('DENY');
    expect(rule.evaluate(ctx('/admin-backup.zip')).action).toBe('DENY');
    expect(rule.evaluate(ctx('/git-guide')).action).toBe('ALLOW');
  });

  it('dryRun logs but does not block', () => {
    const rule = new TripwireRule({ dryRun: true });
    const res = rule.evaluate(ctx('/.env'));
    expect(res.action).toBe('ALLOW');
    expect(res.metadata?.dryRun).toBe(true);
    expect(res.reason).toMatch(/Tripwire hit/);
  });
});

describe('honeytoken()', () => {
  it('generates a hidden, non-followable link pointing at its tripwire path', () => {
    const hp = honeytoken();
    expect(hp.path.startsWith('/__wd/')).toBe(true);
    expect(hp.linkHtml).toContain(`href="${hp.path}"`);
    expect(hp.linkHtml).toContain('aria-hidden="true"');
    expect(hp.linkHtml).toContain('rel="nofollow noindex"');
    expect(hp.linkHtml).toMatch(/position:absolute;left:-9999px/);
  });

  it('generates unique tokens, honors basePath and fixed token', () => {
    expect(honeytoken().path).not.toBe(honeytoken().path);
    expect(honeytoken({ basePath: '/trap/' }).path.startsWith('/trap/')).toBe(true);
    expect(honeytoken({ token: 'fixed' }).path).toBe('/__wd/fixed');
  });
});

describe('tripwire() through the RuleEngine', () => {
  it('a honeytoken hit produces a DENY + a recorded violation', () => {
    const hp = honeytoken({ token: 'deadbeef' });
    const engine = new RuleEngine([tripwire({ paths: [hp.path] })]);

    const allow = engine.evaluate(ctx('/products'));
    expect(allow.action).toBe('ALLOW');
    expect(allow.violations).toHaveLength(0);

    const deny = engine.evaluate(ctx(hp.path));
    expect(deny.action).toBe('DENY');
    expect(deny.rule).toBe('tripwire');
    expect(deny.violations.length).toBeGreaterThan(0);
  });
});
