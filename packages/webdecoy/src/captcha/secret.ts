/** HMAC secret validation for PoW/token signing. */

/** The placeholder secret from the FCaptcha reference — never valid in prod. */
export const INSECURE_DEFAULT_SECRET = 'dev-secret-change-in-production';

/**
 * Validate an HMAC signing secret. Throws when the secret is missing/empty, or
 * when it is the insecure default while `NODE_ENV === 'production'`. In
 * non-production environments a missing secret falls back to the insecure
 * default (with the returned flag set) so local development works out of the box.
 */
export function resolveSecret(secret?: string): string {
  const isProd = process.env.NODE_ENV === 'production';

  if (!secret || secret.length === 0) {
    if (isProd) {
      throw new Error(
        'WebDecoy captcha: a `secret` is required in production. Set a strong random value (e.g. `openssl rand -hex 32`).',
      );
    }
    return INSECURE_DEFAULT_SECRET;
  }

  if (isProd && secret === INSECURE_DEFAULT_SECRET) {
    throw new Error(
      'WebDecoy captcha: the default development secret cannot be used in production. Set a strong random `secret`.',
    );
  }

  return secret;
}
