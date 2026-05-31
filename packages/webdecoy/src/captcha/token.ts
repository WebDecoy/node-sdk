/**
 * Session token issuance and verification.
 *
 * Ported from FCaptcha server.js `generateToken`/`verifyToken` + `tokenStore`.
 * Tokens are base64url-encoded JSON with an HMAC signature, a 5-minute expiry,
 * an IP-hash binding, and single-use replay protection.
 */

import { createHash, createHmac, timingSafeEqual } from 'crypto';
import type { TokenVerification } from './types';

const TOKEN_TTL_SECONDS = 300;

/** Tracks consumed token signatures to prevent replay. */
export interface TokenStore {
  /** Returns false if the signature was already consumed. */
  markUsed(sig: string): boolean;
  isUsed(sig: string): boolean;
}

export class InMemoryTokenStore implements TokenStore {
  private usedTokens = new Set<string>();

  markUsed(sig: string): boolean {
    if (this.usedTokens.has(sig)) return false;
    this.usedTokens.add(sig);
    if (Math.random() < 0.1 && this.usedTokens.size > 50000) this.usedTokens.clear();
    return true;
  }

  isUsed(sig: string): boolean {
    return this.usedTokens.has(sig);
  }
}

export interface TokenManagerOptions {
  secret: string;
  store?: TokenStore;
}

interface TokenPayload {
  site_key: string;
  timestamp: number;
  score: number;
  ip_hash: string;
  sig?: string;
}

export class TokenManager {
  private readonly secret: string;
  private readonly store: TokenStore;

  constructor(options: TokenManagerOptions) {
    this.secret = options.secret;
    this.store = options.store ?? new InMemoryTokenStore();
  }

  /** Issue a signed, IP-bound token for a passing request. */
  issue(ip: string, siteKey: string, score: number): string {
    const data: TokenPayload = {
      site_key: siteKey,
      timestamp: Math.floor(Date.now() / 1000),
      score: Math.round(score * 1000) / 1000,
      ip_hash: createHash('sha256').update(ip).digest('hex').slice(0, 8),
    };

    const payload = JSON.stringify(data, Object.keys(data).sort());
    data.sig = createHmac('sha256', this.secret).update(payload).digest('hex');

    return Buffer.from(JSON.stringify(data)).toString('base64url');
  }

  /** Verify a token: signature, expiry, replay, and optional IP binding. */
  verify(token: string, ip: string | null = null): TokenVerification {
    let decoded: TokenPayload;
    try {
      decoded = JSON.parse(Buffer.from(token, 'base64url').toString());
    } catch (e) {
      return { valid: false, reason: e instanceof Error ? e.message : 'invalid_token' };
    }

    if (Date.now() / 1000 - decoded.timestamp > TOKEN_TTL_SECONDS) {
      return { valid: false, reason: 'expired' };
    }

    const sig = decoded.sig;
    if (!sig) return { valid: false, reason: 'invalid_signature' };
    delete decoded.sig;

    const payload = JSON.stringify(decoded, Object.keys(decoded).sort());
    const expectedSig = createHmac('sha256', this.secret).update(payload).digest('hex');

    const sigBuf = Buffer.from(sig);
    const expectedBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
      return { valid: false, reason: 'invalid_signature' };
    }

    if (this.store.isUsed(sig)) {
      return { valid: false, reason: 'token_already_used' };
    }

    if (ip) {
      const expectedIpHash = createHash('sha256').update(ip).digest('hex').slice(0, 8);
      if (decoded.ip_hash !== expectedIpHash) {
        return { valid: false, reason: 'ip_mismatch' };
      }
    }

    this.store.markUsed(sig);

    return {
      valid: true,
      site_key: decoded.site_key,
      timestamp: decoded.timestamp,
      score: decoded.score,
      ip_hash: decoded.ip_hash,
    };
  }
}
