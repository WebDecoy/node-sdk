/**
 * User-Agent parsing and bot-pattern matching. Ported from FCaptcha detection.js.
 */

export interface UserAgentInfo {
  browser: string | null;
  os: string | null;
  isMobile: boolean;
  isBot: boolean;
  botName: string | null;
}

/** UA substrings that indicate a non-browser HTTP client / crawler. */
export const BOT_UA_PATTERNS: RegExp[] = [
  /bot/i, /spider/i, /crawler/i, /scraper/i, /curl/i, /wget/i,
  /python/i, /java\//i, /httpie/i, /postman/i, /insomnia/i,
  /axios/i, /node-fetch/i, /go-http/i, /okhttp/i,
];

const MOBILE_UA_PATTERN = /mobile|android|iphone|ipad|ipod/;

/** True when the UA looks like a mobile device. */
export function isMobileUA(userAgent: string): boolean {
  return MOBILE_UA_PATTERN.test((userAgent || '').toLowerCase());
}

/** Extract browser/OS/bot info from a User-Agent string. */
export function parseUserAgent(ua: string): UserAgentInfo {
  const info: UserAgentInfo = {
    browser: null,
    os: null,
    isMobile: false,
    isBot: false,
    botName: null,
  };

  for (const pattern of BOT_UA_PATTERNS) {
    const match = ua.match(pattern);
    if (match) {
      info.isBot = true;
      info.botName = match[0];
      return info;
    }
  }

  if (ua.includes('Edg/')) info.browser = 'Edge';
  else if (ua.includes('Chrome/')) info.browser = 'Chrome';
  else if (ua.includes('Firefox/')) info.browser = 'Firefox';
  else if (ua.includes('Safari/') && !ua.includes('Chrome')) info.browser = 'Safari';

  if (ua.includes('Windows')) info.os = 'Windows';
  else if (ua.includes('Mac OS X') || ua.includes('Macintosh')) info.os = 'macOS';
  else if (ua.includes('Linux')) info.os = 'Linux';
  else if (ua.includes('Android')) {
    info.os = 'Android';
    info.isMobile = true;
  } else if (ua.includes('iPhone') || ua.includes('iPad')) {
    info.os = 'iOS';
    info.isMobile = true;
  }

  if (ua.includes('Mobile')) info.isMobile = true;

  return info;
}
