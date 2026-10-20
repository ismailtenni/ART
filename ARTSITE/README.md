# ISMAILTENNI ART - setup (Cloudflare Pages + D1 accounts)
1. Cloudflare dashboard > Storage & Databases > D1 > Create database (name: ismailtenni-art).
2. Open it > Console > paste everything from schema.sql > Execute.
3. Workers & Pages > your Pages project > Settings > Bindings > Add > D1 database. Variable name: DB. Pick ismailtenni-art. Save, then redeploy.
4. Upload this whole folder (index.html, _worker.js, assets/) to the project (or push it to GitHub).
Sign up / Log in then works on the site. Passwords are stored hashed (PBKDF2), never as plain text.
Note: there is no email verification or "forgot password" yet.

Likes and comments use the same database. If you already ran schema.sql before, run it again (safe to repeat) so the likes and comments tables are created.
Only logged-in members can like or comment. Members can delete their own comments.

Owner moderation: in Pages > Settings > Variables and Secrets, add ADMIN_EMAIL = your login email. That account can then delete any comment.

IF CLOUDFLARE SHOWS "Uploading a Pages _worker.js file as an asset" (Workers deploy): this folder already includes wrangler.jsonc and .assetsignore.
Open wrangler.jsonc and replace PASTE_YOUR_DATABASE_ID_HERE with your D1 Database ID (Cloudflare > Storage & Databases > D1 > ismailtenni-art > copy the Database ID).
