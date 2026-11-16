/**
 * FreeDNS domain publisher — Google Apps Script web app.
 *
 * Pairs with doc.py. On each POST it creates a NEW Google Doc containing the
 * current working domains and their expiry times, shares it with the supplied
 * emails, records it as the current doc, and trashes the docs it created before.
 *
 * ── Setup ────────────────────────────────────────────────────────────────────
 * 1. script.google.com → New project → paste this file in.
 * 2. Deploy → New deployment → type "Web app".
 *      Execute as:  Me
 *      Who has access:  Anyone                (required for the unauthenticated
 *                                               POST from doc.py; a Workspace/
 *                                               school account may forbid this —
 *                                               see the note at the bottom)
 * 3. Copy the /exec URL into the web UI as "Doc Web App URL".
 * 4. Set the shared secret. Either:
 *      a) Project Settings → Script properties → add AUTH_PASSWORD = <secret>, or
 *      b) leave it unset: the FIRST request's password becomes AUTH_PASSWORD.
 *    Put the same value in the web UI as "Doc Auth Password".
 *
 * Re-deploy (Manage deployments → edit → new version) after editing this file.
 */

var PROP = PropertiesService.getScriptProperties();

function doPost(e) {
  try {
    var body = JSON.parse((e && e.postData && e.postData.contents) || '{}');

    var authErr = checkAuth_(body.password);
    if (authErr) return json_({ ok: false, error: authErr });

    var title = String(body.title || ('Domains ' + new Date().toISOString()));
    var text = String(body.text || '');
    var emails = (body.emails || []).filter(function (x) { return x; });

    // 1. Create the new doc and write the body.
    var doc = DocumentApp.create(title);
    var b = doc.getBody();
    b.clear();
    b.appendParagraph(text).setFontFamily('Courier New');
    doc.saveAndClose();

    var id = doc.getId();
    var file = DriveApp.getFileById(id);

    // 2. Share. Link-sharing may be blocked by a Workspace admin; don't let that
    //    stop the per-email sharing, so guard each call independently.
    try {
      file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    } catch (err) { /* link sharing disabled by policy */ }
    emails.forEach(function (addr) {
      try { file.addViewer(addr); } catch (err) { /* e.g. external sharing blocked */ }
    });

    // 3. Trash the docs we published before, then record this as current.
    var prev = [];
    try { prev = JSON.parse(PROP.getProperty('DOC_IDS') || '[]'); } catch (err) { prev = []; }
    prev.forEach(function (oldId) {
      if (oldId && oldId !== id) {
        try { DriveApp.getFileById(oldId).setTrashed(true); } catch (err) {}
      }
    });
    PROP.setProperty('DOC_IDS', JSON.stringify([id]));
    PROP.setProperty('CURRENT_ID', id);

    return json_({ ok: true, id: id, url: doc.getUrl(), shared: emails.length });
  } catch (err) {
    return json_({ ok: false, error: String(err) });
  }
}

// GET ?password=<secret> → the current doc's URL (used by doc.get_current_url).
function doGet(e) {
  var given = (e && e.parameter && e.parameter.password) || '';
  var authErr = checkAuth_(given);
  if (authErr) return json_({ ok: false, error: authErr });

  var id = PROP.getProperty('CURRENT_ID') || '';
  if (!id) return json_({ ok: true, url: '' });
  try {
    return json_({ ok: true, id: id, url: DriveApp.getFileById(id).getUrl() });
  } catch (err) {
    return json_({ ok: true, url: '' });
  }
}

// Returns '' when authorized, else an error string. Bootstraps AUTH_PASSWORD
// from the first request if it has never been set.
function checkAuth_(given) {
  given = String(given || '');
  var expected = PROP.getProperty('AUTH_PASSWORD');
  if (!expected) {
    if (!given) return 'AUTH_PASSWORD not set and no password supplied';
    PROP.setProperty('AUTH_PASSWORD', given);
    return '';
  }
  // Constant-ish comparison (length then chars) to avoid trivial timing leaks.
  if (given.length !== expected.length) return 'invalid password';
  var diff = 0;
  for (var i = 0; i < expected.length; i++) {
    diff |= given.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0 ? '' : 'invalid password';
}

function json_(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

/*
 * Note on school / Workspace accounts: if the Drive admin disables "Anyone"
 * web-app access, doc.py's anonymous POST will be blocked and you'll get an
 * HTML sign-in page instead of JSON (doc.py reports exactly that). In that case
 * deploy the script from a personal Google account, or one whose admin allows
 * public web apps and external link-sharing.
 */
