# PropertyPlug101

A responsive React/Vite property marketplace with an Express API and a local SQLite database.

## Run locally

Use Node.js 20.19+ or 22.12+ and npm. From this folder in the VS Code terminal:

```powershell
npm install
npm run dev
```

The Vite website opens at `http://localhost:5173`. The API starts at `http://127.0.0.1:4000`; Vite forwards `/api` and `/uploads` requests to it. Keep the terminal open while using the site. Stop both servers with **Ctrl+C**.

## Backend features

- Account registration and sign-in with hashed passwords and secure HTTP-only session cookies.
- Create property listings with up to five JPEG, PNG, or WebP photos (8 MB per image).
- Save listing images to `server/uploads/` and records to `server/data/propertyplug101.sqlite`.
- Save agent enquiries in SQLite.
- View published listings on the home page.

The local database and uploaded images persist between restarts. This starter is for local development; it does not yet include email delivery, password reset, an admin review workflow, or production hosting/security configuration. Do not use it for real customer data until those are added.

## Security protections

- Helmet security headers on API responses; Vercel site headers are configured in vercel.json.
- Per-IP request limits on sign-in/registration, enquiries, and property submissions.
- State-changing browser requests are checked against the configured site origin. Set APP_ORIGIN to the exact production origin (for example, https://your-domain.example) before running in production.
- New accounts require a 15-character passphrase (up to 64 characters); existing accounts can still sign in.
- Property uploads have size/count limits, are written to a staging folder, decoded and checked for JPEG/PNG/WebP content, then re-encoded as WebP with metadata removed and dimensions limited.
- Secret files named .env or .env.* are ignored by Git. Keep production secrets in the hosting provider environment settings.

The built-in rate-limit store is in memory and is suitable for this single-process development server. Before running multiple production instances, configure a shared rate-limit store and set TRUST_PROXY_HOPS only to the number of trusted proxies in front of the API. Vercel/AWS hosting also requires durable database and object storage for production data and uploaded photos.
