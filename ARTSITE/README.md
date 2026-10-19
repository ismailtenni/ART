# ISMAILTENNI ART - setup (Cloudflare Pages + D1 accounts)
1. Cloudflare dashboard > Storage & Databases > D1 > Create database (name: ismailtenni-art).
2. Open it > Console > paste everything from schema.sql > Execute.
3. Workers & Pages > your Pages project > Settings > Bindings > Add > D1 database. Variable name: DB. Pick ismailtenni-art. Save, then redeploy.
4. Upload this whole folder (index.html, _worker.js, assets/) to the project (or push it to GitHub).
Sign up / Log in then works on the site. Passwords are stored hashed (PBKDF2), never as plain text.
Note: there is no email verification or "forgot password" yet.
