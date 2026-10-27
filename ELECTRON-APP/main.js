// ART-ISMAILTENNI - opens the live website in its own window, like a normal Windows program.
// To point the program at another address, change SITE below.
const { app, BrowserWindow, shell, Menu, session } = require('electron');
const path = require('path');

const SITE = 'https://artist.ismailtenni6.workers.dev/';
const SITE_HOST = new URL(SITE).hostname;

const OFFLINE = `<html><head><meta charset="utf-8"></head>
<body style="margin:0;background:#050816;color:#fff;font-family:Segoe UI,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center">
<div><h2 style="font-weight:400;letter-spacing:.2em">ART-ISMAILTENNI</h2>
<p style="color:#b7c4dc">No internet connection.<br>Please connect and try again.</p>
<a href="${SITE}" style="display:inline-block;margin-top:14px;padding:12px 28px;border-radius:999px;border:1px solid #fff;color:#fff;text-decoration:none">Try again</a>
</div></body></html>`;

function isSite(url) {
  try { return new URL(url).hostname === SITE_HOST; } catch (e) { return false; }
}

let win = null;

function createWindow() {
  win = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 420,
    minHeight: 600,
    backgroundColor: '#050816',
    title: 'ART-ISMAILTENNI',
    icon: path.join(__dirname, 'icon.png'),
    autoHideMenuBar: true,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, devTools: false }
  });
  Menu.setApplicationMenu(null);

  // protect the artwork: no screenshots or screen recording of this window, no right-click menu, no developer tools
  try { win.setContentProtection(true); } catch (err) {}
  win.webContents.on('context-menu', (ev) => ev.preventDefault());
  win.webContents.on('devtools-opened', () => { try { win.webContents.closeDevTools(); } catch (err) {} });
  // only files the site itself makes for the owner (backups, request photos, app files) may be downloaded; never artwork pictures
  session.defaultSession.on('will-download', (ev, item) => {
    const u = item.getURL() || '';
    const ok = u.startsWith('blob:') || u.startsWith('data:') || /\/api\/(reqimg|msgimg|dl)\//.test(u);
    if (!ok) ev.preventDefault();
  });

  win.loadURL(SITE);

  // links to other websites (WhatsApp, Instagram, ...) open in the normal browser
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (isSite(url)) return { action: 'allow' };
    shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e, url) => {
    if (!isSite(url) && !url.startsWith('data:')) {
      e.preventDefault();
      shell.openExternal(url);
    }
  });

  // no internet: show a friendly page
  win.webContents.on('did-fail-load', (e, code, desc, url, isMainFrame) => {
    if (isMainFrame && code !== -3) {
      win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(OFFLINE));
    }
  });

  // F11 = full screen, Ctrl+R = reload
  win.webContents.on('before-input-event', (e, input) => {
    if (input.type !== 'keyDown') return;
    const k = (input.key || '').toLowerCase();
    if (input.key === 'F12' || (input.control && input.shift && ['i', 'j', 'c'].includes(k)) || (input.control && ['s', 'u', 'p'].includes(k))) { e.preventDefault(); return; }
    if (input.key === 'F11') { win.setFullScreen(!win.isFullScreen()); e.preventDefault(); }
    if (input.control && input.key.toLowerCase() === 'r') { win.reload(); e.preventDefault(); }
  });

  win.on('closed', () => { win = null; });
}

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (win) { if (win.isMinimized()) win.restore(); win.focus(); }
  });
  app.whenReady().then(() => {
    session.defaultSession.setPermissionRequestHandler((wc, permission, cb) => {
      cb(['fullscreen', 'clipboard-sanitized-write', 'notifications', 'media'].includes(permission));
    });
    createWindow();
    app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  });
  app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
}
