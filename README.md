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
