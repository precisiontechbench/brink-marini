# Brink & Marini, Inc. Invoices

Installable web app (PWA) for weekly freight invoices. Static files, served from GitHub Pages.

**Invoice header:** invoice #, customer (from the Customers list, blank by default), date (warns unless Friday or Saturday), billing terms (Due on receipt, Net 7, Net 15, Net 30; due date fills in from the date), due date, status (Draft / Submitted / Paid), notes.

**Line items:** Date, Freight Bill #, Description, Ticket #, Product / Item, Quantity (Tons), Pay Rate, Amount (= quantity x pay rate, rounded to cents). Totals for tons and dollars sit under the lines.

**Autosave:** every edit is saved to the browser at once and sent to GitHub about one second after you stop typing. The top bar shows "Saving…" then "All changes saved". Unsent changes are kept encrypted in the browser and recovered on next sign-in.

**Storage:** data is encrypted (AES-256-GCM) in the browser and written to a separate **private** GitHub repository. The login vault `config.js` holds the GitHub token, encrypted with your username and password.

## First-time setup
1. Create two repos: this app (public, for GitHub Pages) and a **private** data repo, e.g. `brink-marini-data`.
2. Create a fine-grained token limited to the data repo with Contents: Read and write.
3. Turn on GitHub Pages for the app repo (main, root) and open the site.
4. Fill in the setup screen, download `config.js`, commit it over the placeholder, and push.
5. On a phone, use "Add to Home Screen" / "Install app".

Also: search, status filter, duplicate invoice, print / PDF, CSV export, backup, auto-lock after idle.
