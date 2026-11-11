# Brink & Marini Invoices: working notes for Claude

Installable web app (PWA) for Brink & Marini, Inc. weekly freight invoices. Deploys to GitHub Pages from `main`.
Data is encrypted in the browser and saved to a separate private data repository.

- `config.js` is the owner's encrypted login vault. Never overwrite it, and never commit passwords, tokens or keys.
- `app.js` is the whole app, `index.html` holds the styles, `sw.js` caches the app shell.
- Start each session with `git fetch` and `git status`. Never force-push.
