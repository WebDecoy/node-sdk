# WebDecoy Captcha Example

Self-hosted captcha demo: the [`@webdecoy/client`](../../packages/client) checkbox
widget in the browser, the [`@webdecoy/express`](../../packages/express) captcha
endpoints + in-process detection engine on the server.

## Run

```bash
npm install          # from the repo root (workspaces)
npm run build        # build the @webdecoy/* packages
cd examples/captcha-express
npm run dev          # → http://localhost:3000
```

Open http://localhost:3000, tick the captcha, then **Log in**. The widget:

1. Fetches a proof-of-work challenge from `GET /__webdecoy/challenge`.
2. Collects ~40 behavioral/environmental/fingerprint signals.
3. Solves the PoW (binding the signals hash) and posts to `POST /__webdecoy/verify`.
4. Receives a signed session token, which the form submits to `/login`, where
   the server verifies it with `Captcha.verifyToken()`.

## Notes

- Set `WEBDECOY_SECRET` for a real signing secret (required when
  `NODE_ENV=production`).
- This demo uses in-memory stores. For multi-instance / serverless deployments,
  provide a shared `challengeStore` / `tokenStore` (Redis).
