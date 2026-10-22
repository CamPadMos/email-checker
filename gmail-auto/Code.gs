/**
 * Email Checker — Gmail auto-scanner (Google Apps Script)
 * ------------------------------------------------------
 * Every 10 minutes, checks new inbox emails for phishing signs and labels them:
 *   Email Checker/Phishing     (score >= 60)
 *   Email Checker/Suspicious   (score 25–59)
 *   Email Checker/Checked      (every email it has already reviewed)
 *
 * Runs entirely inside YOUR Google account. No email content is sent anywhere.
 * It never deletes anything. Moving phishing to Spam is OFF by default.
 *
 * Two ways to use it:
 *  A) Just for you: paste in script.google.com, run setup(), authorize.
 *  B) For anyone (web app): Deploy → New deployment → Web app
 *       Execute as: "User accessing the web app"
 *       Who has access: "Anyone with a Google account"
 *     Share the web app link. Each person authorizes their OWN account and
 *     turns protection on/off from a simple page. You never see their email.
 */

// ------------------------------------------------------------- settings ---
const SETTINGS = {
  minutesBetweenScans: 10,          // allowed: 1, 5, 10, 15, 30
  lookBack: '2d',                   // only scan emails newer than this
  maxThreadsPerRun: 40,             // keeps each run well under Google's time limit
  moveDangerToSpam: false,          // set to true to auto-move "Phishing" to Spam
  markDangerImportant: false,       // set to true to also star phishing emails
  labelRoot: 'Email Checker',
};

const LABELS = {
  danger: SETTINGS.labelRoot + '/Phishing',
  warn: SETTINGS.labelRoot + '/Suspicious',
  checked: SETTINGS.labelRoot + '/Checked',
};

// ---------------------------------------------------------------- rules ---
const BRANDS = ['floridablue.com', 'microsoft.com', 'office365.com', 'google.com', 'paypal.com',
  'amazon.com', 'apple.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'docusign.com',
  'linkedin.com', 'outlook.com', 'netflix.com', 'usps.com', 'fedex.com', 'irs.gov', 'hccs.edu', 'uh.edu'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at'];
const RISKY_TLDS = ['zip', 'mov', 'xyz', 'top', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'work', 'rest', 'support'];
const RISKY_EXT = ['.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.iso', '.img', '.html', '.htm',
  '.hta', '.lnk', '.docm', '.xlsm', '.zip', '.rar', '.7z'];
const URGENCY = [/urgent/i, /immediately/i, /within 24 hours/i, /account (will be )?(suspended|locked|closed)/i,
  /verify your (account|identity|information)/i, /unusual (sign-in|activity)/i, /final notice/i,
  /action required/i, /confirm your password/i, /(coverage|benefits) will be (terminated|cancell?ed)/i,
  /urgente/i, /inmediatamente/i, /cuenta (será )?(suspendida|bloqueada|cerrada)/i,
  /verifi(que|ca) (su|tu) (cuenta|identidad)/i, /acción requerida/i, /en las próximas 24 horas/i];
const SENSITIVE = /(password|contraseña|ssn|social security|member id|credit card|tarjeta de crédito|routing number|número de cuenta)/i;
const POINTS = { high: 30, medium: 15, low: 5 };

// -------------------------------------------------------------- helpers ---
function domainOf(a) { const m = String(a || '').match(/@([\w.-]+)/); return m ? m[1].toLowerCase() : ''; }
function rootDomain(h) { const p = String(h || '').toLowerCase().split('.').filter(String); return p.length >= 2 ? p.slice(-2).join('.') : (h || ''); }
function hostOf(u) { const m = String(u).match(/^https?:\/\/(?:[^@\/]*@)?([^\/:?#]+)/i); return m ? m[1].toLowerCase() : ''; }
function hasUserInfo(u) { return /^https?:\/\/[^\/?#]*@/i.test(u); }
function lev(a, b) {
  const d = []; for (let j = 0; j <= b.length; j++) d[j] = j;
  for (let i = 1; i <= a.length; i++) {
    let prev = d[0]; d[0] = i;
    for (let j = 1; j <= b.length; j++) { const t = d[j]; d[j] = Math.min(d[j] + 1, d[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1)); prev = t; }
  }
  return d[b.length];
}
function lookalike(host) {
  const d = rootDomain(host); if (!d) return null;
  for (const b of BRANDS) {
    if (d === b) return null;
    const name = b.split('.')[0], dist = lev(d, b);
    if (dist > 0 && dist <= 2) return b;
    if (name.length >= 4 && d.indexOf(name) >= 0) return b;
  }
  return null;
}
function stripTags(html) { return String(html || '').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' '); }
function extractLinks(html) {
  const out = []; const re = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi; let m;
  while ((m = re.exec(html || ''))) out.push({ href: m[1].trim(), text: stripTags(m[2]).trim() });
  return out;
}

// ------------------------------------------------------------- analysis ---
/**
 * mail = { from, replyTo, subject, authResults, returnPath, html, plain, attachments: [names] }
 * Returns { score, level: 'danger'|'warn'|'safe', findings: [{check, severity, detail}] }
 */
function analyzeMail(mail) {
  const F = []; const add = (check, severity, detail) => F.push({ check, severity, detail });
  const fromDomain = domainOf(mail.from);
  const display = String(mail.from || '').split('<')[0].replace(/"/g, '').trim().toLowerCase();

  const auth = String(mail.authResults || '').toLowerCase();
  ['spf', 'dkim', 'dmarc'].forEach(mech => {
    const m = auth.match(new RegExp(mech + '=(\\w+)'));
    if (m && ['fail', 'softfail', 'none', 'permerror'].indexOf(m[1]) >= 0)
      add('Sender authentication failed', 'high', mech.toUpperCase() + '=' + m[1]);
  });

  [['Reply-To', mail.replyTo], ['Return-Path', mail.returnPath]].forEach(([label, value]) => {
    const other = domainOf(value);
    if (other && fromDomain && rootDomain(other) !== rootDomain(fromDomain))
      add(label + ' goes to a different domain', 'medium', other + ' vs ' + fromDomain);
  });

  for (const b of BRANDS) {
    const name = b.split('.')[0];
    if (name.length >= 4 && display.replace(/\s+/g, '').indexOf(name) >= 0 && rootDomain(fromDomain) !== b) {
      add('Display name impersonates a brand', 'high', '"' + display + '" from ' + fromDomain); break;
    }
  }
  const lb = lookalike(fromDomain);
  if (lb) add('Look-alike sender domain', 'high', fromDomain + ' imitates ' + lb);

  const links = extractLinks(mail.html);
  const allText = [mail.subject, mail.plain, stripTags(mail.html)].join('\n');
  const hits = [];
  URGENCY.forEach(r => { const m = allText.match(r); if (m && hits.indexOf(m[0].toLowerCase()) < 0) hits.push(m[0].toLowerCase()); });
  if (hits.length) add('Pressure / urgency language', hits.length >= 3 ? 'high' : 'medium', hits.slice(0, 4).join(', '));
  if (SENSITIVE.test(allText)) add('Asks for sensitive information', 'high', 'passwords, IDs or financial data');

  const urls = {};
  (String(mail.plain || '').match(/https?:\/\/[^\s"'<>)]+/g) || []).forEach(u => urls[u] = true);
  links.forEach(l => { if (/^https?:/i.test(l.href)) urls[l.href] = true; });

  links.forEach(l => {
    const shown = (l.text.match(/([\w-]+\.)+[a-z]{2,}/i) || [])[0], real = hostOf(l.href);
    if (shown && real && rootDomain(shown) !== rootDomain(real)) add('Deceptive link text', 'high', 'shows ' + shown + ', goes to ' + real);
  });
  Object.keys(urls).forEach(u => {
    const host = hostOf(u); if (!host) return;
    const isIp = /^[\d.]+$/.test(host);
    if (isIp) add('Link to a raw IP address', 'high', host);
    if (SHORTENERS.indexOf(host) >= 0) add('Shortened link', 'medium', u);
    const tld = host.split('.').pop(); if (RISKY_TLDS.indexOf(tld) >= 0) add('Risky domain ending', 'medium', host);
    const l2 = lookalike(host); if (l2 && !isIp) add('Look-alike link domain', 'high', host + ' imitates ' + l2);
    if (hasUserInfo(u)) add('Disguised link (@ trick)', 'high', u);
  });

  (mail.attachments || []).forEach(name => {
    const ext = (String(name).match(/\.[^.]+$/) || [''])[0].toLowerCase();
    if (RISKY_EXT.indexOf(ext) >= 0) add('Risky attachment', 'high', name);
  });

  const seen = {}; const findings = F.filter(f => { const k = f.check + f.detail; if (seen[k]) return false; seen[k] = true; return true; });
  const score = Math.min(100, findings.reduce((s, f) => s + POINTS[f.severity], 0));
  const level = score >= 60 ? 'danger' : score >= 25 ? 'warn' : 'safe';
  return { score, level, findings };
}

// --------------------------------------------------------------- Gmail ---
function userSetting_(key, fallback) {
  const v = PropertiesService.getUserProperties().getProperty(key);
  return v === null ? fallback : v === 'true';
}
function saveStats_(scanned, flagged) {
  const props = PropertiesService.getUserProperties();
  props.setProperties({
    lastRun: new Date().toISOString(),
    totalScanned: String(Number(props.getProperty('totalScanned') || 0) + scanned),
    totalFlagged: String(Number(props.getProperty('totalFlagged') || 0) + flagged),
  });
}

function getOrCreateLabel_(name) { return GmailApp.getUserLabelByName(name) || GmailApp.createLabel(name); }

function messageToMail_(msg) {
  let attachments = [];
  try { attachments = msg.getAttachments({ includeInlineImages: false }).map(a => a.getName()); } catch (e) {}
  return {
    from: msg.getFrom(),
    replyTo: msg.getReplyTo(),
    subject: msg.getSubject(),
    authResults: msg.getHeader('Authentication-Results'),
    returnPath: msg.getHeader('Return-Path'),
    html: msg.getBody(),
    plain: msg.getPlainBody(),
    attachments,
  };
}

/** Main job — runs on the timer. Safe to run by hand too. */
function scanInbox() {
  const lock = LockService.getUserLock();
  if (!lock.tryLock(5000)) return;  // a previous run is still going
  try {
    const labels = { danger: getOrCreateLabel_(LABELS.danger), warn: getOrCreateLabel_(LABELS.warn), checked: getOrCreateLabel_(LABELS.checked) };
    const query = 'in:inbox newer_than:' + SETTINGS.lookBack + ' -label:"' + LABELS.checked + '"';
    const threads = GmailApp.search(query, 0, SETTINGS.maxThreadsPerRun);
    const log = [];

    threads.forEach(thread => {
      let worst = { score: 0, level: 'safe', findings: [] };
      thread.getMessages().forEach(msg => {
        const r = analyzeMail(messageToMail_(msg));
        if (r.score > worst.score) worst = r;
      });
      if (worst.level === 'danger') {
        thread.addLabel(labels.danger);
        if (userSetting_('star', SETTINGS.markDangerImportant)) thread.getMessages().forEach(m => m.star());
        if (userSetting_('spam', SETTINGS.moveDangerToSpam)) thread.moveToSpam();
      } else if (worst.level === 'warn') {
        thread.addLabel(labels.warn);
      }
      thread.addLabel(labels.checked);
      if (worst.level !== 'safe') log.push(worst.score + ' | ' + thread.getFirstMessageSubject() + ' | ' + worst.findings.map(f => f.check).join('; '));
    });

    saveStats_(threads.length, log.length);
    console.log('Scanned ' + threads.length + ' thread(s). Flagged ' + log.length + '.');
    log.forEach(l => console.log(l));
    return { scanned: threads.length, flagged: log.length };
  } finally {
    lock.releaseLock();
  }
}

/** Run once: creates labels, scans now, and turns on the automatic timer. */
function setup() {
  uninstall();
  Object.keys(LABELS).forEach(k => getOrCreateLabel_(LABELS[k]));
  ScriptApp.newTrigger('scanInbox').timeBased().everyMinutes(SETTINGS.minutesBetweenScans).create();
  scanInbox();
  console.log('Email Checker is ON. It will scan every ' + SETTINGS.minutesBetweenScans + ' minutes.');
}

/** Turns the automatic scanning OFF. */
function uninstall() {
  ScriptApp.getProjectTriggers().filter(t => t.getHandlerFunction() === 'scanInbox').forEach(t => ScriptApp.deleteTrigger(t));
  console.log('Automatic scanning is OFF.');
}


// ------------------------------------------------------------- web app ---
// These functions power the simple on/off page (doGet). Each visitor runs
// them under their own Google account.

function doGet() {
  return HtmlService.createHtmlOutput(PAGE_HTML)
    .setTitle('Email Checker — Automatic protection')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

function isActive_() {
  return ScriptApp.getProjectTriggers().some(t => t.getHandlerFunction() === 'scanInbox');
}

function getStatus() {
  const p = PropertiesService.getUserProperties();
  return {
    email: Session.getActiveUser().getEmail() || Session.getEffectiveUser().getEmail(),
    active: isActive_(),
    lastRun: p.getProperty('lastRun'),
    totalScanned: Number(p.getProperty('totalScanned') || 0),
    totalFlagged: Number(p.getProperty('totalFlagged') || 0),
    spam: userSetting_('spam', SETTINGS.moveDangerToSpam),
    star: userSetting_('star', SETTINGS.markDangerImportant),
    minutes: SETTINGS.minutesBetweenScans,
  };
}
function turnOn()  { setup(); return getStatus(); }
function turnOff() { uninstall(); return getStatus(); }
function scanNow() { const r = scanInbox() || { scanned: 0, flagged: 0 }; const s = getStatus(); s.justScanned = r; return s; }
function saveOption(key, value) {
  if (['spam', 'star'].indexOf(key) < 0) throw new Error('Unknown option');
  PropertiesService.getUserProperties().setProperty(key, String(!!value));
  return getStatus();
}

const PAGE_HTML = `<!DOCTYPE html><html><head><base target="_top"><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Atkinson+Hyperlegible:wght@400;700&family=Bricolage+Grotesque:opsz,wght@12..96,700;12..96,800&display=swap" rel="stylesheet">
<style>
:root{--bg:#EEF2F7;--surface:#fff;--s2:#F6F8FB;--ink:#14213D;--soft:#4A5672;--line:#D5DCE8;--accent:#2F5BD3;--on:#fff;--safe:#1F7A5C;--safebg:#E3F3EC;--danger:#B42318;--dangerbg:#FCE7E4;color-scheme:light}
@media(prefers-color-scheme:dark){:root{--bg:#0E1626;--surface:#16213A;--s2:#1B2843;--ink:#E7ECF5;--soft:#A6B2CC;--line:#2C3A5A;--accent:#7C9CF5;--on:#0E1626;--safe:#5BC9A2;--safebg:#12352B;--danger:#FF8A7A;--dangerbg:#3D1A17;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:400 1.05rem/1.6 "Atkinson Hyperlegible",system-ui,sans-serif}
.wrap{max-width:36rem;margin:0 auto;padding:2rem 1.25rem 3rem}
h1{font:800 2rem/1.15 "Bricolage Grotesque",system-ui,sans-serif;margin:0 0 .5rem}
.lede{color:var(--soft);margin:0 0 1.5rem}
.card{background:var(--surface);border:1.5px solid var(--line);border-radius:16px;padding:1.25rem;margin-bottom:1rem}
.status{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap}
.pill{font-weight:700;padding:.3rem .9rem;border-radius:999px}
.pill.on{background:var(--safebg);color:var(--safe)}.pill.off{background:var(--dangerbg);color:var(--danger)}
.who{color:var(--soft);font-size:.95rem;overflow-wrap:anywhere}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:.5rem;margin-top:1rem}
.stats div{background:var(--s2);border-radius:10px;padding:.6rem;text-align:center}
.stats b{display:block;font:700 1.4rem "Bricolage Grotesque",sans-serif}.stats span{font-size:.8rem;color:var(--soft)}
.btns{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1rem}
button{font:inherit;border-radius:10px;padding:.7rem 1.2rem;cursor:pointer}
.main{background:var(--accent);color:var(--on);border:0;font-weight:700}
.alt{background:none;color:var(--ink);border:1.5px solid var(--line)}
button:disabled{opacity:.5;cursor:wait}
label{display:flex;gap:.6rem;align-items:flex-start;margin:.6rem 0;cursor:pointer}
label input{margin-top:.35rem;width:1.1rem;height:1.1rem}
label small{display:block;color:var(--soft)}
.msg{min-height:1.5rem;color:var(--soft);font-size:.95rem;margin-top:.75rem}
ul{padding-left:1.2rem;color:var(--soft);margin:.25rem 0 0}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
</style></head><body><div class="wrap">
<h1 data-t="title"></h1><p class="lede" data-t="lede"></p>
<div class="card">
  <div class="status"><span class="pill off" id="pill">…</span><span class="who" id="who"></span></div>
  <div class="stats">
    <div><b id="scanned">–</b><span data-t="scanned"></span></div>
    <div><b id="flagged">–</b><span data-t="flagged"></span></div>
    <div><b id="last">–</b><span data-t="last"></span></div>
  </div>
  <div class="btns">
    <button class="main" id="toggle"></button>
    <button class="alt" id="scan" data-t="scan"></button>
  </div>
  <p class="msg" id="msg" role="status"></p>
</div>
<div class="card">
  <label><input type="checkbox" id="spam"><span><span data-t="spamT"></span><small data-t="spamD"></small></span></label>
  <label><input type="checkbox" id="star"><span><span data-t="starT"></span><small data-t="starD"></small></span></label>
</div>
<div class="card"><strong data-t="howT"></strong><ul id="how"></ul></div>
</div>
<script>
const es=(navigator.language||'').toLowerCase().startsWith('es');
const T=es?{title:'Protección automática',lede:'Revisa tus correos nuevos de Gmail y marca los que parecen phishing, aunque Gmail los deje pasar.',
on:'Activada',off:'Apagada',turnOn:'Activar protección',turnOff:'Apagar protección',scan:'Revisar ahora',
scanned:'revisados',flagged:'marcados',last:'última revisión',never:'nunca',
spamT:'Mover el phishing a Spam',spamD:'Apagado por defecto. Te recomendamos esperar unos días para confirmar que no marca correos buenos.',
starT:'Destacar los correos de phishing',starD:'Les pone una estrella para que los veas fácil.',
howT:'Cómo funciona',how:['Corre dentro de tu propia cuenta de Google. Tus correos no se envían a ningún otro lugar.','Nunca borra nada. Solo agrega las etiquetas “Email Checker/Phishing” y “Email Checker/Suspicious”.','Puedes apagarlo aquí o quitar el acceso en myaccount.google.com → Seguridad.'],
working:'Trabajando…',doneOn:m=>'Listo. Revisaremos tus correos cada '+m+' minutos.',doneOff:'Protección apagada.',
doneScan:r=>'Revisados '+r.scanned+' correos nuevos, '+r.flagged+' marcados.',err:'Algo falló: '}
:{title:'Automatic protection',lede:'Checks your new Gmail messages and labels the ones that look like phishing, even when Gmail lets them through.',
on:'On',off:'Off',turnOn:'Turn on protection',turnOff:'Turn off protection',scan:'Check now',
scanned:'checked',flagged:'flagged',last:'last check',never:'never',
spamT:'Move phishing to Spam',spamD:'Off by default. We suggest waiting a few days to confirm it doesn’t flag good emails.',
starT:'Star phishing emails',starD:'Adds a star so they’re easy to spot.',
howT:'How it works',how:['It runs inside your own Google account. Your emails are never sent anywhere else.','It never deletes anything. It only adds the labels “Email Checker/Phishing” and “Email Checker/Suspicious”.','Turn it off here anytime, or remove access at myaccount.google.com → Security.'],
working:'Working…',doneOn:m=>'Done. We’ll check your email every '+m+' minutes.',doneOff:'Protection is off.',
doneScan:r=>'Checked '+r.scanned+' new email(s), flagged '+r.flagged+'.',err:'Something went wrong: '};
document.documentElement.lang=es?'es':'en';
document.querySelectorAll('[data-t]').forEach(e=>e.textContent=T[e.dataset.t]);
T.how.forEach(x=>{const li=document.createElement('li');li.textContent=x;document.getElementById('how').appendChild(li)});
const $=id=>document.getElementById(id);let S=null;
function draw(s){S=s;$('pill').textContent=s.active?T.on:T.off;$('pill').className='pill '+(s.active?'on':'off');
 $('who').textContent=s.email||'';$('scanned').textContent=s.totalScanned;$('flagged').textContent=s.totalFlagged;
 $('last').textContent=s.lastRun?new Date(s.lastRun).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}):T.never;
 $('toggle').textContent=s.active?T.turnOff:T.turnOn;$('spam').checked=s.spam;$('star').checked=s.star;}
function busy(b){['toggle','scan','spam','star'].forEach(i=>$(i).disabled=b);if(b)$('msg').textContent=T.working}
function call(fn,arg,after){busy(true);const r=google.script.run.withSuccessHandler(s=>{busy(false);draw(s);$('msg').textContent=after?after(s):''})
 .withFailureHandler(e=>{busy(false);$('msg').textContent=T.err+e.message});arg===undefined?r[fn]():r[fn].apply(r,arg)}
$('toggle').onclick=()=>S&&S.active?call('turnOff',undefined,()=>T.doneOff):call('turnOn',undefined,s=>T.doneOn(s.minutes));
$('scan').onclick=()=>call('scanNow',undefined,s=>T.doneScan(s.justScanned));
$('spam').onchange=e=>call('saveOption',['spam',e.target.checked]);
$('star').onchange=e=>call('saveOption',['star',e.target.checked]);
call('getStatus');
</script></body></html>`;

// Node test hook (ignored by Apps Script)
if (typeof module !== 'undefined') module.exports = { analyzeMail };
