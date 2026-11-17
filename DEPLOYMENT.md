# Asbily Controller — Deployment & Operations Guide

## Architecture

`Frontend (HTML/CSS/JS)` → `Cloudflare Workers API Gateway` → `Selected Backend Provider (Vercel / Railway / Render)` → `Database / Firebase / R2 / Lemon Squeezy`

---

## 1. Local Development (Native Node.js 20+)

```bash
cp .env.example .env
npm install
npm run dev
```

- Landing page: `http://localhost:3000/`
- Controller Dashboard: `http://localhost:3000/dashboard`
- Health check: `http://localhost:3000/health`
- Run tests: `npm test`

On first visit to `/dashboard`, use **Authentication → Bootstrap First Super Administrator** (or set `ASBILY_ADMIN_EMAIL` and `ASBILY_ADMIN_PASSWORD` in your environment).

---

## 2. Cloudflare Workers API Gateway (`worker/`)

1. Install Wrangler globally or run via `npx wrangler`.
2. Edit `worker/wrangler.toml`:
   - Set non-secret provider URLs under `[vars]` (`VERCEL_BACKEND_URL`, `RAILWAY_BACKEND_URL`, `RENDER_BACKEND_URL`).
   - Optionally bind KV (`CONTROLLER_CONFIG`) for dynamic dashboard routing and R2 (`ASBILY_STORAGE`) for object storage.
   - Uncomment `routes` to attach a custom domain (e.g. `api.asbily.com/*`).
3. Configure secrets using Wrangler (never commit secrets to Git):

```bash
cd worker
npx wrangler secret put GATEWAY_SIGNING_SECRET
npx wrangler secret put GATEWAY_ADMIN_TOKEN
npx wrangler secret put VERCEL_API_KEY
npx wrangler secret put VERCEL_API_SECRET
npx wrangler secret put RAILWAY_API_KEY
npx wrangler secret put RAILWAY_API_SECRET
npx wrangler secret put RENDER_API_KEY
npx wrangler secret put RENDER_API_SECRET
```

4. Deploy the Worker:

```bash
npx wrangler deploy
```

---

## 3. Vercel Backend Deployment

Uses `vercel.json`, `api/index.js`, and `api/lemon-squeezy/index.js`.

1. Connect the GitHub repository in Vercel (`framework: null`).
2. Add environment variables in Vercel Project Settings (matching `.env.example` keys required for your deployment).
3. Deploy via Git push or `npx vercel --prod`.

---

## 4. Railway Backend Deployment

Uses `railway.json` (`startCommand: "node server.js"`, `healthcheckPath: "/health"`).

1. Create a new Railway service from your GitHub repository.
2. Railway automatically detects `railway.json` and runs `node server.js` on `process.env.PORT`.
3. Add required secrets (`CONTROLLER_SESSION_SECRET`, `CONTROLLER_ENCRYPTION_KEY`, `ASBILY_ADMIN_EMAIL`, `ASBILY_ADMIN_PASSWORD`, etc.) in Railway Variables.

---

## 5. Render Backend Deployment

Uses `render.yaml` (`startCommand: "node server.js"`, `healthCheckPath: "/health"`).

1. Create a **Blueprint** or **Web Service** in Render pointing to your GitHub repository.
2. Render auto-generates `CONTROLLER_SESSION_SECRET` and `CONTROLLER_ENCRYPTION_KEY` from `render.yaml` and prompts for any `sync: false` secrets.
