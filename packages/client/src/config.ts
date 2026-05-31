/**
 * Shared runtime configuration for the browser widget.
 *
 * Replaces the mutable `FCaptcha.serverUrl` global from the reference client so
 * the collectors and PoW manager can read the configured server origin without
 * a circular import on the public API object.
 *
 * Endpoint paths align with the `@webdecoy/node` captcha handler
 * (`createCaptchaEndpoints`), whose default base path is `/__webdecoy`.
 */

let serverUrl: string | null = null;
let basePath = '/__webdecoy';

/** Origin that serves the WebDecoy captcha endpoints. */
export function getServerUrl(): string | null {
  return serverUrl;
}

export function setServerUrl(url: string | null): void {
  serverUrl = url;
}

/** Base path the captcha endpoints are mounted under (default `/__webdecoy`). */
export function getBasePath(): string {
  return basePath;
}

export function setBasePath(path: string): void {
  basePath = path.replace(/\/$/, '');
}
