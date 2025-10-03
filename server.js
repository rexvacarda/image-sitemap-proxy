// server.js (Lottery + Back-in-Stock, multilingual)
// Email, admin page, Shopify eligibility, MX validation, dedupe, public "current" endpoints

const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const dns = require('dns').promises;
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3005;
const host = '0.0.0.0';

// Ensure fetch exists (Node >=18 has it; for <18 we lazy-load node-fetch v3 ESM)
const ensureFetch = async () => {
  if (typeof fetch !== 'undefined') return fetch;
  const { default: nodeFetch } = await import('node-fetch');
  return nodeFetch;
};

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true })); // for <form> posts

// ---------- Email transporter ----------
const mailer = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT || 587),
  secure: String(process.env.EMAIL_PORT) === '465', // true if SSL (465)
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// ---------- SQLite DB (file) ----------
const dbPath = process.env.DB_PATH || 'lottery.db';
const db = new sqlite3.Database(dbPath);
console.log('DB path in use:', dbPath);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      productId INTEGER,
      name TEXT,
      startPrice REAL,
      increment REAL,
      endAt TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS unsubscribes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      productId INTEGER,
      email TEXT,
      locale TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS bis_subscribers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      product_handle TEXT,
      product_title TEXT,
      variant_id TEXT,
      locale TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS winners (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      productId INTEGER,
      email TEXT,
      drawnAt TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS bis_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      productId TEXT,
      email TEXT,
      locale TEXT,
      createdAt TEXT
    )
  `);

  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_bis_unique ON bis_requests (productId, email)`);
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_unique ON entries (productId, email)`);

  // Try to add entries.locale if it wasn't there (ignore if exists)
  db.run(`ALTER TABLE entries ADD COLUMN locale TEXT`, err => {
    if (err && !String(err.message || err).toLowerCase().includes('duplicate column name')) {
      console.warn('ALTER TABLE entries ADD COLUMN locale warning:', err.message || err);
    }
  });

  // === email_campaigns table =======================================
  db.run(`
    CREATE TABLE IF NOT EXISTS email_campaigns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      subject TEXT NOT NULL,
      html TEXT NOT NULL,
      segment TEXT,                 -- e.g. 'en-gb' (NULL/blank => all)
      per_hour_limit INTEGER DEFAULT 500,
      total_cap INTEGER DEFAULT 100000,     -- safety cap
      sent_count INTEGER DEFAULT 0,
      failed_count INTEGER DEFAULT 0,
      skipped_count INTEGER DEFAULT 0,
      since_id INTEGER DEFAULT 0,   -- resume cursor for Shopify REST
      status TEXT DEFAULT 'active', -- 'active' | 'paused' | 'done' | 'cancelled'
      last_run_at TEXT,             -- last batch run timestamp
      lock_until TEXT,              -- soft lock to avoid concurrent runs (SQLite datetime)
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // Helpful indexes
  db.run(`CREATE INDEX IF NOT EXISTS idx_campaign_status ON email_campaigns(status)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_campaign_since ON email_campaigns(since_id)`);
});

// ---------- Helpers ----------
const BLOCKED_EMAIL_DOMAINS = (process.env.BLOCKED_EMAIL_DOMAINS || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

function normEmail(e) { return String(e || '').trim().toLowerCase(); }

function isValidEmailFormat(email) {
  const re = /^[^\s@]+@[^\s@]+\.[A-Za-z0-9-]{2,}$/;
  return re.test(email);
}

async function withTimeout(promise, ms = 2000) {
  return await Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error('DNS timeout')), ms))
  ]);
}

async function isDeliverableEmail(email) {
  const domain = String(email).split('@')[1]?.toLowerCase();
  if (!domain) return false;
  if (BLOCKED_EMAIL_DOMAINS.includes(domain)) return false;

  try {
    const mx = await withTimeout(dns.resolveMx(domain));
    if (Array.isArray(mx) && mx.length > 0) return true;
  } catch (_) { /* ignore */ }

  try {
    const a = await withTimeout(dns.resolve(domain));
    if (Array.isArray(a) && a.length > 0) return true;
  } catch (_) { /* ignore */ }

  return false;
}

function normLocale(loc) { return String(loc || 'en').toLowerCase(); }
function shortLocale(loc) { return normLocale(loc).split('-')[0]; }

// ---------- Unsubscribe helpers (single, unified set) ----------
const UNSUB_SECRET = process.env.UNSUB_SECRET || process.env.UNSUBSCRIBE_SECRET || 'change-me';

function signUnsub(email) {
  return crypto.createHmac('sha256', UNSUB_SECRET)
    .update(normEmail(email))
    .digest('hex')
    .slice(0, 32);
}

function buildUnsubLink(email) {
  const base = (process.env.PUBLIC_BASE_URL || `http://localhost:${port}`).replace(/\/+$/, '');
  const t = signUnsub(email);
  return `${base}/u?e=${encodeURIComponent(normEmail(email))}&t=${t}`;
}

function verifyUnsub(email, token) {
  if (!token) return false;
  try {
    const expected = signUnsub(email);
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(token)));
  } catch {
    return false;
  }
}

function isUnsubscribed(email) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT 1 FROM unsubscribes WHERE email = ? LIMIT 1`, [normEmail(email)], (err, row) => {
      if (err) return reject(err);
      resolve(!!row);
    });
  });
}

function withUnsubFooter(html, email) {
  const link = buildUnsubLink(email);
  const brand = process.env.BRAND_NAME || 'our store';
  const footer = `
    <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
    <p style="font:13px/1.45 Arial,sans-serif;color:#666;margin:0">
      You’re receiving this because you subscribed at ${brand}.
      <a href="${link}">Unsubscribe</a>.
    </p>`;

  if (/<\/body>\s*<\/html>\s*$/i.test(html)) {
    return html.replace(/<\/body>\s*<\/html>\s*$/i, `${footer}</body></html>`);
  }
  if (/<\/body>/i.test(html)) {
    return html.replace(/<\/body>/i, `${footer}</body>`);
  }
  return String(html || '') + footer;
}

function listUnsubHeader(email) {
  const httpLink = buildUnsubLink(email);
  const mailto = (process.env.UNSUBSCRIBE_MAILTO || '').trim();
  return mailto ? `<mailto:${mailto}>, <${httpLink}>` : `<${httpLink}>`;
}

// ---------- Shopify helpers ----------
async function shopifyGraphQL(query, variables = {}) {
  const f = await ensureFetch();
  const shop = process.env.SHOPIFY_STORE;
  const token = process.env.SHOPIFY_ADMIN_API_KEY;
  if (!shop || !token) throw new Error('Missing SHOPIFY_STORE or SHOPIFY_ADMIN_API_KEY');

  const resp = await f(`https://${shop}/admin/api/2025-01/graphql.json`, {
    method: 'POST',
    headers: {
      'X-Shopify-Access-Token': token,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify({ query, variables })
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Shopify GQL ${resp.status}: ${text}`);
  }
  const data = await resp.json();
  if (data.errors) throw new Error(`Shopify GQL errors: ${JSON.stringify(data.errors)}`);
  return data.data;
}

async function fetchAllSubscribedCustomersFromShopify() {
  const out = [];
  let cursor = null;
  const q = `
    query Customers($cursor: String) {
      customers(first: 250, after: $cursor, query: "email_marketing_consent:subscribed") {
        edges {
          cursor
          node { email locale emailMarketingConsent { state } }
        }
        pageInfo { hasNextPage }
      }
    }
  `;
  while (true) {
    const data = await shopifyGraphQL(q, { cursor });
    const edges = data?.customers?.edges || [];
    for (const e of edges) {
      const n = e.node;
      if (!n?.email) continue;
      const email = normEmail(n.email);
      const loc = (n.locale || '').toLowerCase();
      const short = loc.includes('-') ? loc.split('-')[0] : loc;
      out.push({ email, short_locale: short || '' });
    }
    if (!data?.customers?.pageInfo?.hasNextPage) break;
    cursor = edges[edges.length - 1]?.cursor || null;
    if (!cursor) break;
  }
  // dedupe
  const seen = new Set();
  const deduped = [];
  for (const r of out) {
    if (seen.has(r.email)) continue;
    seen.add(r.email);
    deduped.push(r);
  }
  return deduped;
}

function ensureAdmin(req, res) {
  const pass = req.query.pass || req.headers['x-admin-pass'] || req.body?.pass;
  if (pass !== process.env.ADMIN_PASS) {
    res.status(403).send('Forbidden: wrong password');
    return false;
  }
  return true;
}

function isAdmin(req) {
  const pass = req.query.pass || req.body?.pass || req.headers['x-admin-pass'];
  return pass && pass === process.env.ADMIN_PASS;
}

// ---------- Email content builders ----------
function buildEmail(locale, title, claimLink) {
  const l = normLocale(locale), s = shortLocale(locale);
  const t = {
    en: { subject: `You won: ${title}!`, hello: `🎉 Congratulations!`, body: `You’ve won the lottery for <strong>${title}</strong>.`, ctaLead: `Click below to claim your prize:`, cta: `Claim your prize`, reply: `Please reply to this email to claim your prize.`, copyHelp: `If the button doesn’t work, copy this link:` },
    de: { subject: `Sie haben gewonnen: ${title}!`, hello: `🎉 Herzlichen Glückwunsch!`, body: `Sie haben die Verlosung für <strong>${title}</strong> gewonnen.`, ctaLead: `Klicken Sie unten, um Ihren Gewinn einzulösen:`, cta: `Gewinn einlösen`, reply: `Bitte antworten Sie auf diese E-Mail, um Ihren Gewinn zu beanspruchen.`, copyHelp: `Falls die Schaltfläche nicht funktioniert, kopieren Sie diesen Link:` },
    fr: {
      subject: `Vous avez gagné : ${title} !`,
      hello: `🎉 Félicitations !`,
      body: `Vous avez remporté la loterie pour <strong>${title}</strong>.`,
      ctaLead: `Cliquez ci-dessous pour récupérer votre lot :`,
      cta: `Récupérer mon lot`,
      reply: `Veuillez répondre à cet e-mail pour récupérer votre lot.`,
      copyHelp: `Si le bouton ne fonctionne pas, copiez ce lien :`
    },
    es: {
      subject: `¡Has ganado: ${title}!`,
      hello: `🎉 ¡Enhorabuena!`,
      body: `Has ganado la lotería de <strong>${title}</strong>.`,
      ctaLead: `Haz clic abajo para reclamar tu premio:`,
      cta: `Reclamar premio`,
      reply: `Responde a este correo para reclamar tu premio.`,
      copyHelp: `Si el botón no funciona, copia este enlace:`
    },
    it: {
      subject: `Hai vinto: ${title}!`,
      hello: `🎉 Congratulazioni!`,
      body: `Hai vinto la lotteria per <strong>${title}</strong>.`,
      ctaLead: `Clicca qui sotto per riscattare il premio:`,
      cta: `Riscatta il premio`,
      reply: `Rispondi a questa email per riscattare il premio.`,
      copyHelp: `Se il pulsante non funziona, copia questo link:`
    },
    nl: {
      subject: `Je hebt gewonnen: ${title}!`,
      hello: `🎉 Gefeliciteerd!`,
      body: `Je hebt de loterij voor <strong>${title}</strong> gewonnen.`,
      ctaLead: `Klik hieronder om je prijs te claimen:`,
      cta: `Prijs claimen`,
      reply: `Beantwoord deze e-mail om je prijs te claimen.`,
      copyHelp: `Werkt de knop niet? Kopieer deze link:`
    },
    da: {
      subject: `Du har vundet: ${title}!`,
      hello: `🎉 Tillykke!`,
      body: `Du har vundet lodtrækningen om <strong>${title}</strong>.`,
      ctaLead: `Klik herunder for at få din præmie:`,
      cta: `Hent præmien`,
      reply: `Svar på denne e-mail for at få din præmie.`,
      copyHelp: `Hvis knappen ikke virker, så kopier dette link:`
    },
    sv: {
      subject: `Du har vunnit: ${title}!`,
      hello: `🎉 Grattis!`,
      body: `Du har vunnit lotteriet för <strong>${title}</strong>.`,
      ctaLead: `Klicka nedan för att hämta ditt pris:`,
      cta: `Hämta priset`,
      reply: `Svara på detta mejl för att hämta ditt pris.`,
      copyHelp: `Om knappen inte fungerar, kopiera denna länk:`
    },
    nb: {
      subject: `Du har vunnet: ${title}!`,
      hello: `🎉 Gratulerer!`,
      body: `Du har vunnet lotteriet for <strong>${title}</strong>.`,
      ctaLead: `Klikk nedenfor for å hente premien:`,
      cta: `Hent premien`,
      reply: `Svar på denne e-posten for å hente premien.`,
      copyHelp: `Hvis knappen ikke fungerer, kopier denne lenken:`
    },
    fi: {
      subject: `Voitit: ${title}!`,
      hello: `🎉 Onnittelut!`,
      body: `Voitit arvonnassa tuotteen <strong>${title}</strong>.`,
      ctaLead: `Napsauta alta lunastaaksesi palkinnon:`,
      cta: `Lunasta palkinto`,
      reply: `Vastaa tähän sähköpostiin lunastaaksesi palkinnon.`,
      copyHelp: `Ellei painike toimi, kopioi tämä linkki:`
    },
    pl: {
      subject: `Wygrałeś/Wygrałaś: ${title}!`,
      hello: `🎉 Gratulacje!`,
      body: `Wygrałeś/Wygrałaś losowanie <strong>${title}</strong>.`,
      ctaLead: `Kliknij poniżej, aby odebrać nagrodę:`,
      cta: `Odbierz nagrodę`,
      reply: `Odpowiedz na tę wiadomość, aby odebrać nagrodę.`,
      copyHelp: `Jeśli przycisk nie działa, skopiuj ten link:`
    },
    pt: {
      subject: `Você ganhou: ${title}!`,
      hello: `🎉 Parabéns!`,
      body: `Você ganhou o sorteio de <strong>${title}</strong>.`,
      ctaLead: `Clique abaixo para resgatar o prêmio:`,
      cta: `Resgatar prêmio`,
      reply: `Responda a este e-mail para resgatar seu prêmio.`,
      copyHelp: `Se o botão não funcionar, copie este link:`
    },
    cs: {
      subject: `Vyhráli jste: ${title}!`,
      hello: `🎉 Gratulujeme!`,
      body: `Vyhráli jste v loterii o <strong>${title}</strong>.`,
      ctaLead: `Klikněte níže pro převzetí výhry:`,
      cta: `Vyžádat výhru`,
      reply: `Odpovězte na tento e-mail pro převzetí výhry.`,
      copyHelp: `Pokud tlačítko nefunguje, zkopírujte tento odkaz:`
    },
    sk: {
      subject: `Vyhrali ste: ${title}!`,
      hello: `🎉 Gratulujeme!`,
      body: `Vyhrali ste v lotérii o <strong>${title}</strong>.`,
      ctaLead: `Kliknite nižšie a vyzdvihnite si výhru:`,
      cta: `Vyzdvihnúť výhru`,
      reply: `Odpovedzte na tento e-mail, aby ste získali výhru.`,
      copyHelp: `Ak tlačidlo nefunguje, skopírujte tento odkaz:`
    },
    sl: {
      subject: `Zmagali ste: ${title}!`,
      hello: `🎉 Čestitke!`,
      body: `Zmagali ste v žrebanju za <strong>${title}</strong>.`,
      ctaLead: `Kliknite spodaj za prevzem nagrade:`,
      cta: `Prevzemi nagrado`,
      reply: `Odgovorite na to e-pošto za prevzem nagrade.`,
      copyHelp: `Če gumb ne deluje, kopirajte to povezavo:`
    },
    ro: {
      subject: `Ai câștigat: ${title}!`,
      hello: `🎉 Felicitări!`,
      body: `Ai câștigat loteria pentru <strong>${title}</strong>.`,
      ctaLead: `Apasă mai jos pentru a-ți revendica premiul:`,
      cta: `Revendică premiul`,
      reply: `Răspunde la acest e-mail pentru a-ți revendica premiul.`,
      copyHelp: `Dacă butonul nu funcționează, copiază acest link:`
    },
    hu: {
      subject: `Nyertél: ${title}!`,
      hello: `🎉 Gratulálunk!`,
      body: `Megnyerted a <strong>${title}</strong> sorsolását.`,
      ctaLead: `Kattints lentebb a nyereményed átvételéhez:`,
      cta: `Nyeremény átvétele`,
      reply: `Válaszolj erre az e-mailre a nyereményed átvételéhez.`,
      copyHelp: `Ha a gomb nem működik, másold ezt a hivatkozást:`
    },
    bg: {
      subject: `Спечелихте: ${title}!`,
      hello: `🎉 Поздравления!`,
      body: `Вие спечелихте томболата за <strong>${title}</strong>.`,
      ctaLead: `Кликнете по-долу, за да получите наградата:`,
      cta: `Вземете наградата`,
      reply: `Отговорете на този имейл, за да получите наградата.`,
      copyHelp: `Ако бутонът не работи, копирайте този линк:`
    },
    el: {
      subject: `Κερδίσατε: ${title}!`,
      hello: `🎉 Συγχαρητήρια!`,
      body: `Κερδίσατε την κλήρωση για <strong>${title}</strong>.`,
      ctaLead: `Κάντε κλικ παρακάτω για να παραλάβετε το έπαθλο:`,
      cta: `Παραλαβή επάθλου`,
      reply: `Απαντήστε σε αυτό το email για να παραλάβετε το έπαθλο.`,
      copyHelp: `Αν δεν λειτουργεί το κουμπί, αντιγράψτε αυτόν τον σύνδεσμο:`
    },
    tr: {
      subject: `Kazandınız: ${title}!`,
      hello: `🎉 Tebrikler!`,
      body: `<strong>${title}</strong> çekilişini kazandınız.`,
      ctaLead: `Ödülünüzü almak için aşağıya tıklayın:`,
      cta: `Ödülü al`,
      reply: `Ödülünüzü almak için bu e-postayı yanıtlayın.`,
      copyHelp: `Düğme çalışmazsa bu bağlantıyı kopyalayın:`
    },
    ru: {
      subject: `Вы выиграли: ${title}!`,
      hello: `🎉 Поздравляем!`,
      body: `Вы выиграли розыгрыш <strong>${title}</strong>.`,
      ctaLead: `Нажмите ниже, чтобы получить приз:`,
      cta: `Получить приз`,
      reply: `Ответьте на это письмо, чтобы получить приз.`,
      copyHelp: `Если кнопка не работает, скопируйте эту ссылку:`
    },
    ja: {
      subject: `当選しました：${title}！`,
      hello: `🎉 おめでとうございます！`,
      body: `<strong>${title}</strong> の抽選に当選しました。`,
      ctaLead: `賞品の受け取りは以下をクリック：`,
      cta: `賞品を受け取る`,
      reply: `このメールに返信して賞品を受け取ってください。`,
      copyHelp: `ボタンが動作しない場合は、このリンクをコピーしてください：`
    },
    ko: {
      subject: `당첨을 축하드립니다: ${title}!`,
      hello: `🎉 축하합니다!`,
      body: `<strong>${title}</strong> 추첨에 당첨되셨습니다.`,
      ctaLead: `아래를 클릭해 상품을 수령하세요:`,
      cta: `상품 수령하기`,
      reply: `이 이메일에 회신하여 상품을 수령하세요.`,
      copyHelp: `버튼이 작동하지 않으면 이 링크를 복사하세요:`
    },
    'zh-cn': {
      subject: `您已中奖：${title}！`,
      hello: `🎉 恭喜！`,
      body: `您已中签 <strong>${title}</strong> 抽奖活动。`,
      ctaLead: `点击下方领取奖品：`,
      cta: `领取奖品`,
      reply: `请回复此邮件以领取奖品。`,
      copyHelp: `如果按钮无效，请复制此链接：`
    },
    'zh-tw': {
      subject: `您中獎了：${title}！`,
      hello: `🎉 恭喜！`,
      body: `您已中籤 <strong>${title}</strong> 抽獎活動。`,
      ctaLead: `點擊下方領取獎品：`,
      cta: `領取獎品`,
      reply: `請回覆此郵件以領取獎品。`,
      copyHelp: `如果按鈕無法使用，請複製此連結：`
    },
    vi: {
      subject: `Bạn đã trúng thưởng: ${title}!`,
      hello: `🎉 Chúc mừng!`,
      body: `Bạn đã trúng xổ số cho <strong>${title}</strong>.`,
      ctaLead: `Nhấn bên dưới để nhận phần thưởng:`,
      cta: `Nhận phần thưởng`,
      reply: `Hãy trả lời email này để nhận phần thưởng.`,
      copyHelp: `Nếu nút không hoạt động, hãy sao chép liên kết này:`
    },
    lt: {
      subject: `Jūs laimėjote: ${title}!`,
      hello: `🎉 Sveikiname!`,
      body: `Laimėjote loteriją dėl <strong>${title}</strong>.`,
      ctaLead: `Spustelėkite žemiau, kad atsiimtumėte prizą:`,
      cta: `Atsiimti prizą`,
      reply: `Atsakykite į šį el. laišką, kad atsiimtumėte prizą.`,
      copyHelp: `Jei mygtukas neveikia, nukopijuokite šią nuorodę:`
    },
    hr: {
      subject: `Pobijedili ste: ${title}!`,
      hello: `🎉 Čestitamo!`,
      body: `Pobijedili ste na nagradnoj igri za <strong>${title}</strong>.`,
      ctaLead: `Kliknite dolje za preuzimanje nagrade:`,
      cta: `Preuzmi nagradu`,
      reply: `Odgovorite na ovaj e-mail kako biste preuzeli nagradu.`,
      copyHelp: `Ako gumb ne radi, kopirajte ovu poveznicu:`
    }
  };
  const pack = t[l] || t[s] || t.en;
  const html = `
    <div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
      <h2>${pack.hello}</h2>
      <p>${pack.body}</p>
      ${claimLink ? `
        <p>${pack.ctaLead}</p>
        <p><a href="${claimLink}" style="padding:12px 18px;background:#111;color:#fff;text-decoration:none;border-radius:6px">${pack.cta}</a></p>
        <p style="font-size:13px;color:#666">${pack.copyHelp}<br>${claimLink}</p>
      ` : `<p>${pack.reply}</p>`}
    </div>
  `;
  return { subject: pack.subject, html };
}

function buildEntryConfirmEmail(locale, title) {
  const l = normLocale(locale), s = shortLocale(locale);
  const t = {
    en: { subject: `You're in: ${title}`, body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Thanks—your entry for <strong>${title}</strong> is confirmed.</p><p>We’ll draw at the deadline and email the winner.</p></div>` },
    de: { subject: `Sie sind dabei: ${title}`, body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Danke – Ihre Teilnahme für <strong>${title}</strong> wurde bestätigt.</p><p>Wir losen zum Stichtag aus und benachrichtigen den Gewinner per E-Mail.</p></div>` },
    fr: {
      subject: `Participation confirmée : ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
               <p>Merci — votre participation pour <strong>${title}</strong> est confirmée.</p>
               <p>Nous tirerons au sort à l’échéance et préviendrons le gagnant par e-mail.</p>
             </div>`
    },
    nl: {
      subject: `Je doet mee: ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
               <p>Bedankt — je inschrijving voor <strong>${title}</strong> is bevestigd.</p>
               <p>We loten op de einddatum en mailen de winnaar.</p>
             </div>`
    },
    es: {
      subject: `Estás dentro: ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
               <p>Gracias — tu participación en <strong>${title}</strong> está confirmada.</p>
               <p>Haremos el sorteo en la fecha límite y enviaremos un correo al ganador.</p>
             </div>`
    },
    it: {
      subject: `Sei dentro: ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
               <p>Grazie — la tua partecipazione a <strong>${title}</strong> è confermata.</p>
               <p>Eseguiremo l’estrazione alla scadenza e invieremo un’e-mail al vincitore.</p>
             </div>`
    },
    ja: {
      subject: `参加が確定しました：${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
               <p>ご応募ありがとうございます。<strong>${title}</strong> への参加が確認されました。</p>
               <p>締め切り後に抽選を行い、当選者にメールでご連絡します。</p>
             </div>`
    },
    ko: {
      subject: `참여가 완료되었습니다: ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
               <p>감사합니다. <strong>${title}</strong> 응모가 확인되었습니다.</p>
               <p>마감 후 추첨하여 당첨자에게 이메일로 안내드립니다.</p>
             </div>`
    },
    pl: {
      subject: `Zgłoszenie przyjęte: ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
               <p>Dziękujemy — Twoje zgłoszenie do <strong>${title}</strong> zostało potwierdzone.</p>
               <p>Losowanie odbędzie się w terminie końcowym, a zwycięzca otrzyma e-mail.</p>
             </div>`
    },
    ro: {
      subject: `Ești înscris: ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
               <p>Mulțumim — înscrierea ta pentru <strong>${title}</strong> a fost confirmată.</p>
               <p>Vom face tragerea la sorți la termen și îl vom anunța pe câștigător prin e-mail.</p>
             </div>`
    },
    bg: {
      subject: `Участието ви е потвърдено: ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
               <p>Благодарим — участието ви за <strong>${title}</strong> е потвърдено.</p>
               <p>Жребият ще бъде изтеглен на крайния срок и победителят ще получи имейл.</p>
             </div>`
    },
    ar: {
      subject: `تم تأكيد مشاركتك: ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333;direction:rtl;text-align:right">
               <p>شكرًا لك — تم تأكيد مشاركتك في <strong>${title}</strong>.</p>
               <p>سنُجري السحب عند موعد الإغلاق ونرسل رسالة إلى الفائز عبر البريد الإلكتروني.</p>
             </div>`
    },
    he: {
      subject: `ההרשמה שלך אושרה: ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333;direction:rtl;text-align:right">
               <p>תודה — ההשתתפות שלך ב־<strong>${title}</strong> אושרה.</p>
               <p>נבצע את ההגרלה במועד הסיום ונעדכן את הזוכה במייל.</p>
             </div>`
    },
    sv: {
      subject: `Du är med: ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
               <p>Tack — din anmälan till <strong>${title}</strong> är bekräftad.</p>
               <p>Vi drar en vinnare vid sista datumet och mejlar vinnaren.</p>
             </div>`
    },
    nb: {
      subject: `Du er med: ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
               <p>Takk — påmeldingen din til <strong>${title}</strong> er bekreftet.</p>
               <p>Vi trekker en vinner ved fristen og sender e-post til vinneren.</p>
             </div>`
    },
    fi: {
      subject: `Olet mukana: ${title}`,
      body: `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
               <p>Kiitos — osallistumisesi kohteeseen <strong>${title}</strong> on vahvistettu.</p>
               <p>Arvonta suoritetaan määräaikana ja voittajalle lähetetään sähköposti.</p>
             </div>`
    }
  };
  const pack = t[l] || t[s] || t.en;
  return { subject: pack.subject, html: pack.body };
}

// ---------- BIS i18n ----------
const BIS_I18N = {
  subject: {
    en: 'Back in stock: {{title}}',
    de: 'Wieder auf Lager: {{title}}',
    fr: 'De retour en stock : {{title}}',
    es: '¡De vuelta en stock!: {{title}}',
    it: 'Tornato disponibile: {{title}}',
    nl: 'Terug op voorraad: {{title}}',
    da: 'Tilbage på lager: {{title}}',
    sv: 'Tillbaka i lager: {{title}}',
    nb: 'Tilbake på lager: {{title}}',
    fi: 'Täydennetty varastoon: {{title}}',
    cs: 'Zpět na skladě: {{title}}',
    sk: 'Opäť na sklade: {{title}}',
    sl: 'Spet na zalogi: {{title}}',
    hu: 'Újra készleten: {{title}}',
    ro: 'Înapoi în stoc: {{title}}',
    pl: 'Ponownie w magazynie: {{title}}',
    pt: 'De volta ao estoque: {{title}}',
    bg: 'Отново в наличност: {{title}}',
    el: 'Ξανά διαθέσιμο: {{title}}',
    ru: 'Снова в наличии: {{title}}',
    tr: 'Yeniden stokta: {{title}}',
    vi: 'Có hàng trở lại: {{title}}',
    ja: '再入荷：{{title}}',
    ko: '재입고: {{title}}',
    'zh-cn': '现已到货：{{title}}',
    'zh-tw': '現已到貨：{{title}}'
  },
  body: {
    en: (title, url) => `
      <div style="font-family:Arial,sans-serif;font-size:16px;color:#333">
        <p>Good news — <strong>${title}</strong> is back in stock.</p>
        <p><a href="${url}" style="padding:10px 14px;background:#111;color:#fff;text-decoration:none;border-radius:6px">Shop now</a></p>
      </div>`,
    de: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Gute Nachrichten — <strong>${t}</strong> ist wieder vorrätig.</p><p><a href="${u}" style="padding:10px 14px;background:#111;color:#fff;text-decoration:none;border-radius:6px">Jetzt kaufen</a></p></div>`,
    fr: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Bonne nouvelle — <strong>${t}</strong> est de retour en stock.</p><p><a href="${u}" style="padding:10px 14px;background:#111;color:#fff;text-decoration:none;border-radius:6px">Je commande</a></p></div>`,
    es: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Buenas noticias: <strong>${t}</strong> está de vuelta.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Comprar ahora</a></p></div>`,
    it: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Buone notizie — <strong>${t}</strong> è di nuovo disponibile.</p><p><a href="${u}" style="padding:10px 14px;background:#111;color:#fff;text-decoration:none;border-radius:6px">Acquista ora</a></p></div>`,
    nl: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Goed nieuws — <strong>${t}</strong> is weer op voorraad.</p><p><a href="${u}" style="padding:10px 14px;background:#111;color:#fff;text-decoration:none;border-radius:6px">Nu shoppen</a></p></div>`,
    da: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Gode nyheder — <strong>${t}</strong> er tilbage på lager.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Køb nu</a></p></div>`,
    sv: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Goda nyheter — <strong>${t}</strong> är tillbaka i lager.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Handla nu</a></p></div>`,
    nb: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Godt nytt — <strong>${t}</strong> er tilbake på lager.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Kjøp nå</a></p></div>`,
    fi: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Hyviä uutisia — <strong>${t}</strong> on taas varastossa.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Osta nyt</a></p></div>`,
    cs: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Skvělé zprávy — <strong>${t}</strong> je opět skladem.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Koupit nyní</a></p></div>`,
    sk: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Skvelá správa — <strong>${t}</strong> je opäť na sklade.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Kúpiť teraz</a></p></div>`,
    sl: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Dobre novice — <strong>${t}</strong> je spet na zalogi.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Nakupuj zdaj</a></p></div>`,
    hu: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Jó hír — <strong>${t}</strong> újra készleten van.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Vásárlás</a></p></div>`,
    ro: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Veste bună — <strong>${t}</strong> este din nou în stoc.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Cumpără acum</a></p></div>`,
    pl: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Dobra wiadomość — <strong>${t}</strong> znów jest dostępny.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Kup teraz</a></p></div>`,
    pt: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Boa notícia — <strong>${t}</strong> está de volta ao estoque.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Comprar agora</a></p></div>`,
    bg: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Добра новина — <strong>${t}</strong> отново е наличен.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Купи сега</a></p></div>`,
    el: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Καλά νέα — το <strong>${t}</strong> είναι ξανά διαθέσιμο.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Αγορά τώρα</a></p></div>`,
    ru: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Отличная новость — <strong>${t}</strong> снова в наличии.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Купить</a></p></div>`,
    tr: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Harika haber — <strong>${t}</strong> yeniden stokta.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Hemen al</a></p></div>`,
    vi: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>Tin vui — <strong>${t}</strong> đã có hàng trở lại.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">Mua ngay</a></p></div>`,
    ja: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>朗報です。<strong>${t}</strong> が再入荷しました。</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">今すぐ購入</a></p></div>`,
    ko: (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>좋은 소식 — <strong>${t}</strong> 가 재입고되었습니다.</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">지금 구매</a></p></div>`,
    'zh-cn': (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>好消息 — <strong>${t}</strong> 现已到货。</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">立即购买</a></p></div>`,
    'zh-tw': (t,u)=>`<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>好消息 — <strong>${t}</strong> 現已到貨。</p><p><a href="${u}" style="padding:10px 14px	background:#111;color:#fff;text-decoration:none;border-radius:6px">立即購買</a></p></div>`
  }
};
function pickLoc(str, fallback = 'en') {
  const s = (str || '').toLowerCase();
  if (BIS_I18N.subject[s]) return s;
  const short = s.split('-')[0];
  return BIS_I18N.subject[short] ? short : fallback;
}
function sub(tpl, vars) { return tpl.replace(/{{\s*(\w+)\s*}}/g, (_, k) => (vars[k] ?? '')); }

// === Campaign locking helpers ==================================
async function acquireCampaignLock(id, ms = 4 * 60 * 1000) {
  // Use SQLite datetime math so comparisons with datetime('now') are valid
  return new Promise(resolve => {
    const seconds = Math.max(1, Math.floor(ms / 1000));
    db.run(`
      UPDATE email_campaigns
      SET lock_until = datetime('now', '+' || ? || ' seconds')
      WHERE id = ?
        AND (lock_until IS NULL OR lock_until < datetime('now'))
    `, [seconds, id], function (err) {
      if (err) return resolve(false);
      resolve(this.changes > 0);
    });
  });
}
function releaseCampaignLock(id) {
  db.run(`UPDATE email_campaigns SET lock_until = NULL WHERE id = ?`, [id], () => {});
}

// ---------- Routes ----------

// Unsubscribe (link: /u?e=<email>&t=<token>)
app.get('/u', (req, res) => {
  const email = normEmail(req.query.e);
  const token = String(req.query.t || '');
  if (!email || !verifyUnsub(email, token)) {
    return res.status(400).send(`
      <div style="font:16px Arial,sans-serif;color:#333">
        <p>Invalid or expired unsubscribe link.</p>
      </div>
    `);
  }
  db.run(`INSERT OR IGNORE INTO unsubscribes (email) VALUES (?)`, [email], err => {
    if (err) {
      console.error('Unsubscribe DB error:', err);
      return res.status(500).send(`<div style="font:16px Arial,sans-serif;color:#333">Server error.</div>`);
    }
    return res.send(`
      <div style="font:16px Arial,sans-serif;color:#333">
        <h2 style="margin:0 0 10px 0">You’ve been unsubscribed</h2>
        <p>${email} will no longer receive marketing emails from us.</p>
      </div>
    `);
  });
});

// --- Admin broadcast from Shopify (form)
app.get('/admin/broadcast-shopify', async (req, res) => {
  if (!ensureAdmin(req, res)) return;
  try {
    const rows = await fetchAllSubscribedCustomersFromShopify();
    const counts = {};
    for (const r of rows) counts[r.short_locale || 'en'] = (counts[r.short_locale || 'en'] || 0) + 1;
    const total = rows.length;
    const opts = Object.keys(counts).sort().map(k => `<option value="${k}">${k} (${counts[k]})</option>`).join('');
    res.send(`
      <meta charset="utf-8">
      <style>
        body { font-family:system-ui, Arial, sans-serif; padding:20px; max-width:900px; margin:0 auto; color:#222;}
        .box { border:1px solid #ddd; border-radius:10px; padding:16px; margin-top:16px;}
        label { display:block; margin-top:12px; font-weight:600; }
        input[type="text"]{ width:100%; padding:10px; border:1px solid #ccc; border-radius:8px;}
        textarea{ width:100%; min-height:260px; padding:10px; border:1px solid #ccc; border-radius:8px; font-family:Consolas,monospace;}
        select,button{ padding:10px 12px; border-radius:8px; border:1px solid #999;}
        .row{ display:flex; gap:8px; align-items:center; flex-wrap:wrap;}
        .muted{ color:#666; font-size:13px;}
        .right{ text-align:right;}
        .btn-primary{ background:#111; color:#fff; border-color:#111;}
      </style>
      <h1>Broadcast from Shopify Customers</h1>
      <p class="muted">Total subscribed customers: <strong>${total}</strong></p>
      <div class="box">
        <form method="POST" action="/admin/broadcast-shopify/send?pass=${encodeURIComponent(req.query.pass || '')}">
          <label>Subject</label>
          <input type="text" name="subject" placeholder="Your email subject" required>
          <div class="row">
            <div>
              <label>Segment by language</label>
              <select name="segment" required>
                <option value="all">All locales</option>
                ${opts}
              </select>
            </div>
            <div>
              <label>Test only</label>
              <select name="test_only">
                <option value="yes">Yes (no sends)</option>
                <option value="no">No (send)</option>
              </select>
            </div>
            <div>
              <label>Max send (cap)</label>
              <input type="text" name="max_send" value="2000" style="width:110px">
            </div>
          </div>
          <label>HTML content</label>
          <textarea name="html" placeholder="<div>...</div>" required></textarea>
          <div class="row right"><button type="submit" class="btn-primary">Go</button></div>
        </form>
      </div>
    `);
  } catch (e) {
    console.error('broadcast-shopify form error', e);
    res.status(500).send('Server error');
  }
});

// Send broadcast
app.post('/admin/broadcast-shopify/send', async (req, res) => {
  if (!ensureAdmin(req, res)) return;
  try {
    const f = await ensureFetch();
    let { subject, html, segment, test_only, max_send } = req.body || {};
    subject = String(subject || '').trim();
    html = String(html || '').trim();
    segment = String(segment || 'all').toLowerCase();
    test_only = String(test_only || 'yes') === 'yes';
    max_send = Number(max_send || 2000);
    if (!subject || !html) return res.status(400).send('Missing subject or HTML.');
    const all = await fetchAllSubscribedCustomersFromShopify();
    const filtered = (segment === 'all') ? all : all.filter(r => (r.short_locale || 'en') === segment);
    const toSend = filtered.slice(0, Math.max(0, max_send));

    if (test_only) {
      return res.send(`
        <meta charset="utf-8">
        <div style="font-family:system-ui,Arial,sans-serif;padding:20px;max-width:900px;margin:0 auto">
          <h2>Test Mode (no emails sent)</h2>
          <p><strong>Segment:</strong> ${segment}</p>
          <p><strong>Total candidates:</strong> ${filtered.length}</p>
          <p><strong>Capped to:</strong> ${toSend.length}</p>
          <p><strong>Sample first 20:</strong></p>
          <pre>${toSend.slice(0,20).map(x=>x.email).join('\\n')}</pre>
          <h3>Subject</h3>
          <pre>${subject.replace(/[<>&]/g, s => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[s]))}</pre>
          <h3>HTML Preview</h3>
          <div style="border:1px solid #ddd;border-radius:8px;padding:12px">${html}</div>
        </div>
      `);
    }

    let sent = 0, failed = 0;
    const batchSize = 50;
    for (let i = 0; i < toSend.length; i += batchSize) {
      const batch = toSend.slice(i, i + batchSize);
      const jobs = batch.map(r =>
        mailer.sendMail({
          from: process.env.FROM_EMAIL || process.env.EMAIL_USER,
          to: r.email,
          subject,
          html: withUnsubFooter(html, r.email),
          headers: { 'List-Unsubscribe': listUnsubHeader(r.email) }
        }).then(() => { sent++; }).catch(err => { failed++; console.error('shopify broadcast error', r.email, err); })
      );
      await Promise.allSettled(jobs);
      await new Promise(r => setTimeout(r, 600));
    }
    res.send(`
      <meta charset="utf-8">
      <div style="font-family:system-ui,Arial,sans-serif;padding:20px;max-width:900px;margin:0 auto">
        <h2>Broadcast complete</h2>
        <p><strong>Segment:</strong> ${segment}</p>
        <p><strong>Attempted:</strong> ${toSend.length}</p>
        <p><strong>Sent:</strong> ${sent}</p>
        <p><strong>Failed:</strong> ${failed}</p>
        <p><a href="/admin/broadcast-shopify?pass=${encodeURIComponent(req.query.pass || '')}">← Back</a></p>
      </div>
    `);
  } catch (e) {
    console.error('broadcast-shopify send error', e);
    res.status(500).send('Server error');
  }
});

// ---------- Lottery ----------
app.post('/lottery/create', (req, res) => {
  let { productId, name, startPrice, increment, endAt } = req.body;
  if (productId == null || name == null || endAt == null || String(name).trim() === '') {
    return res.status(400).json({ success: false, message: 'Missing fields' });
  }
  if (startPrice == null || startPrice === '') startPrice = 0;
  if (increment == null || increment === '') increment = 0;

  db.run(
    `INSERT INTO products (productId, name, startPrice, increment, endAt) VALUES (?, ?, ?, ?, ?)`,
    [productId, name, Number(startPrice), Number(increment), endAt],
    function (err) {
      if (err) {
        console.error('Create lottery insert error:', err);
        return res.status(500).json({ success: false, message: 'Server error' });
      }
      res.json({ success: true, productId });
    }
  );
});

app.post('/lottery/enter', async (req, res) => {
  try {
    const f = await ensureFetch();
    let { email, productId, locale } = req.body;
    if (!email || !productId) {
      return res.status(400).json({ success: false, message: 'Missing email or productId' });
    }
    locale = normLocale(locale || 'en');
    email = normEmail(email);

    if (!isValidEmailFormat(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format' });
    }
    const deliverable = await isDeliverableEmail(email);
    if (!deliverable) {
      return res.status(400).json({ success: false, message: 'Please enter a real email address' });
    }

    const shop = process.env.SHOPIFY_STORE;
    const token = process.env.SHOPIFY_ADMIN_API_KEY;
    if (!shop || !token) {
      return res.status(503).json({ success: false, message: 'Eligibility check unavailable. Please try again later.' });
    }

    const url = `https://${shop}/admin/api/2025-01/orders.json?email=${encodeURIComponent(email)}&status=any&limit=1`;
    const resp = await f(url, { method: 'GET', headers: { 'X-Shopify-Access-Token': token, 'Accept': 'application/json' } });
    if (!resp.ok) {
      console.error('Shopify API error', resp.status, await resp.text());
      return res.status(503).json({ success: false, message: 'Eligibility check unavailable. Please try again later.' });
    }
    const data = await resp.json();
    const hasOrder = Array.isArray(data.orders) && data.orders.length > 0;
    if (!hasOrder) {
      return res.status(200).json({ success: false, message: 'Only customers with a past order can enter this lottery.' });
    }

    db.run(`INSERT INTO entries (productId, email, locale) VALUES (?, ?, ?)`,
      [productId, email, locale],
      function (err) {
        if (err) {
          if (String(err).toLowerCase().includes('unique')) {
            return res.status(200).json({ success: true, message: 'You are already entered for this product.' });
          }
          console.error('DB insert error', err);
          return res.status(500).json({ success: false, message: 'Server error' });
        }

        try {
          db.get(`SELECT name FROM products WHERE productId = ?`, [productId], async (_e2, row) => {
            try {
              const title = row?.name || `Product ${productId}`;
              const { subject, html } = buildEntryConfirmEmail(locale, title);
              await mailer.sendMail({
                from: process.env.FROM_EMAIL || process.env.EMAIL_USER,
                to: email,
                subject,
                html
              });
            } catch (mailErr) {
              console.warn('Entry confirmation email failed:', mailErr?.message || mailErr);
            }
          });
        } catch (e) {
          console.warn('Post-insert confirm mail scheduling failed:', e?.message || e);
        }

        res.json({ success: true, message: 'You have been entered into the lottery!' });
      }
    );
  } catch (e) {
    console.error('Enter handler error', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

function saveWinner(productId, email) {
  return new Promise(resolve => {
    db.run(
      `INSERT INTO winners (productId, email, drawnAt) VALUES (?, ?, datetime('now'))`,
      [productId, email],
      (errW) => {
        if (errW) console.error('Failed to store winner:', errW);
        resolve();
      }
    );
  });
}

app.post('/lottery/draw/:productId', (req, res) => {
  const productId = req.params.productId;
  db.all(`SELECT * FROM entries WHERE productId = ?`, [productId], (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'Server error' });
    if (!rows || rows.length === 0) {
      return res.status(400).json({ success: false, message: 'No entries for this product yet.' });
    }
    const winner = rows[Math.floor(Math.random() * rows.length)];
    db.get(`SELECT * FROM products WHERE productId = ?`, [productId], async (_e2, product) => {
      const title = product?.name || `Product ${productId}`;
      const claimPrefix = process.env.CLAIM_URL_PREFIX || '';
      const claimLink = claimPrefix ? `${claimPrefix}${productId}&email=${encodeURIComponent(winner.email)}` : null;
      try {
        await saveWinner(productId, winner.email);
        const { subject, html } = buildEmail(winner.locale || 'en', title, claimLink);
        await mailer.sendMail({ from: process.env.FROM_EMAIL || process.env.EMAIL_USER, to: winner.email, subject, html });
        return res.json({ success: true, message: `Winner drawn and emailed for product ${productId}`, winner: { email: winner.email, locale: winner.locale || 'en' } });
      } catch (errMail) {
        console.error('Email error:', errMail);
        return res.status(200).json({ success: true, message: 'Winner drawn. Email could not be sent.', emailed: false, winner: { email: winner.email, locale: winner.locale || 'en' } });
      }
    });
  });
});

// ---------- Back-in-Stock (BIS) ----------
app.post('/bis/subscribe', async (req, res) => {
  try {
    let { email, product_handle, product_title, variant_id, locale } = req.body || {};
    if (!email || !product_handle) {
      return res.status(400).json({ ok: false, message: 'Missing email or product' });
    }
    email = normEmail(email);
    locale = normLocale(locale || 'en');

    if (!isValidEmailFormat(email)) return res.status(400).json({ ok: false, message: 'Invalid email format' });
    const deliverable = await isDeliverableEmail(email);
    if (!deliverable) return res.status(400).json({ ok: false, message: 'Please enter a real email address' });

    db.run(
      `INSERT INTO bis_subscribers (email, product_handle, product_title, variant_id, locale) VALUES (?, ?, ?, ?, ?)`,
      [email, product_handle, product_title || '', String(variant_id || ''), locale],
      (err) => { if (err) console.error('BIS insert error:', err); }
    );

    // confirmation to subscriber
    const packs = {
      en: { sub: 'We’ll notify you when it’s back', body: `You’ll receive an email as soon as <strong>${product_title || product_handle}</strong> is back in stock.` },
      de: { sub: 'Wir benachrichtigen Sie bei Verfügbarkeit', body: `Sobald <strong>${product_title || product_handle}</strong> wieder verfügbar ist, erhalten Sie eine E-Mail.` }
    };
    const short = shortLocale(locale);
    const p = packs[locale] || packs[short] || packs.en;

    const htmlCustomer = `<div style="font-family:Arial,sans-serif;font-size:16px;color:#333"><p>${p.body}</p></div>`;

    try {
      await mailer.sendMail({ from: process.env.FROM_EMAIL || process.env.EMAIL_USER, to: email, subject: p.sub, html: htmlCustomer });
      const ownerTo = process.env.BIS_NOTIFY_TO || process.env.FROM_EMAIL || process.env.EMAIL_USER;
      if (ownerTo) {
        await mailer.sendMail({
          from: process.env.FROM_EMAIL || process.env.EMAIL_USER,
          to: ownerTo,
          subject: `BIS signup: ${product_title || product_handle}`,
          html: `<div>New BIS request<br>Email: ${email}<br>Product: ${product_title || product_handle}<br>Variant: ${variant_id || '-'}<br>Locale: ${locale}</div>`
        });
      }
    } catch (mailErr) {
      console.error('BIS mail error:', mailErr);
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error('BIS subscribe error:', e);
    return res.status(500).json({ ok: false, message: 'Server error' });
  }
});

// Notify all BIS subscribers for a product
app.post('/bis/notify', async (req, res) => {
  const pass = req.query.pass || req.headers['x-admin-pass'];
  if (pass !== process.env.ADMIN_PASS) return res.status(403).json({ success: false, message: 'Forbidden' });

  const { productId, productTitle, productUrl, localeOverride } = req.body || {};
  if (!productId || !productTitle || !productUrl) {
    return res.status(400).json({ success: false, message: 'Missing productId/productTitle/productUrl' });
  }

  db.all(`SELECT email, locale FROM bis_requests WHERE productId = ?`, [String(productId)], async (err, rows) => {
    if (err) {
      console.error('BIS select error', err);
      return res.status(500).json({ success: false, message: 'DB error' });
    }
    if (!rows || !rows.length) return res.json({ success: true, sent: 0, message: 'No subscribers' });

    let sent = 0, failed = 0;
    for (const r of rows) {
      const loc = pickLoc(localeOverride || r.locale || 'en');
      const subj = sub(BIS_I18N.subject[loc] || BIS_I18N.subject.en, { title: productTitle });
      const html = (BIS_I18N.body[loc] || BIS_I18N.body.en)(productTitle, productUrl);
      try {
        await mailer.sendMail({ from: process.env.FROM_EMAIL || process.env.EMAIL_USER, to: r.email, subject: subj, html });
        sent++;
      } catch (e) {
        console.error('BIS mail error', r.email, e);
        failed++;
      }
    }

    db.run(`DELETE FROM bis_requests WHERE productId = ?`, [String(productId)]);
    res.json({ success: true, sent, failed });
  });
});

// --- ADMIN: List all entries ---
app.get('/admin/entries', (req, res) => {
  const pass = req.query.pass;
  if (pass !== process.env.ADMIN_PASS) return res.status(403).send('Forbidden: Wrong password');

  db.all(`SELECT productId, email FROM entries ORDER BY productId, email`, [], (err, rows) => {
    if (err) return res.status(500).send('DB error');
    const counts = {};
    rows.forEach(r => { counts[r.productId] = (counts[r.productId] || 0) + 1; });

    let html = `<h2>Lottery Entries</h2>`;
    html += `<p>Total entries: ${rows.length}</p><ul>`;
    for (const pid in counts) html += `<li>Product ${pid}: ${counts[pid]} entries</li>`;
    html += `</ul><table border="1" cellpadding="6" style="border-collapse:collapse"><tr><th>Product ID</th><th>Email</th></tr>`;
    rows.forEach(r => { html += `<tr><td>${r.productId}</td><td>${r.email}</td></tr>`; });
    html += `</table>`;
    res.send(html);
  });
});

// --- ADMIN: repair entries (normalize + dedupe) ---
app.post('/admin/repair-entries', (req, res) => {
  const pass = req.query.pass;
  if (pass !== process.env.ADMIN_PASS) return res.status(403).json({ ok: false, message: 'Forbidden' });

  db.serialize(() => {
    db.run(`UPDATE entries SET email = lower(trim(email))`);
    db.run(`
      DELETE FROM entries
      WHERE rowid NOT IN (
        SELECT MIN(rowid) FROM entries GROUP BY productId, email
      )
    `);
    db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_unique ON entries (productId, email)`);
  });
  res.json({ ok: true, repaired: true });
});

// --- ADMIN: list lotteries (active + finished, with entries count & last winner) ---
app.get('/admin/lotteries', (req, res) => {
  const pass = req.query.pass;
  if (pass !== process.env.ADMIN_PASS) {
    return res.status(403).json({ ok: false, message: 'Forbidden' });
  }

  // IMPORTANT: if your endAt was saved in LOCAL time (no timezone),
  // set NOW_SQL to "datetime('now','localtime')" instead of "datetime('now')".
  const NOW_SQL = `datetime('now','localtime')`;

  const sql = `
    WITH
    ec AS (
      SELECT productId, COUNT(*) AS cnt
      FROM entries
      GROUP BY productId
    ),
    lastw AS (
      SELECT productId, MAX(drawnAt) AS lastDraw
      FROM winners
      GROUP BY productId
    )
    SELECT
      p.productId,
      COALESCE(p.name, 'Product ' || p.productId) AS name,
      p.endAt,
      COALESCE(ec.cnt, 0) AS entries,
      w.email AS winnerEmail,
      lastw.lastDraw,
      CASE
        WHEN p.endAt IS NULL OR p.endAt = '' OR datetime(p.endAt) > ${NOW_SQL} THEN 'active'
        ELSE 'finished'
      END AS status
    FROM products p
    LEFT JOIN ec ON ec.productId = p.productId
    LEFT JOIN lastw ON lastw.productId = p.productId
    LEFT JOIN winners w ON w.productId = p.productId AND w.drawnAt = lastw.lastDraw
    ORDER BY
  CASE
    WHEN p.endAt IS NULL OR p.endAt = '' OR datetime(p.endAt) > ${NOW_SQL} THEN 0
    ELSE 1
  END ASC,
  CASE
    WHEN p.endAt IS NULL OR p.endAt = '' THEN 1 ELSE 0
  END ASC,
  CASE
    WHEN datetime(p.endAt) > ${NOW_SQL} THEN datetime(p.endAt)
  END ASC,
  CASE
    WHEN p.endAt IS NOT NULL AND p.endAt <> '' AND datetime(p.endAt) <= ${NOW_SQL} THEN datetime(p.endAt)
  END DESC
  `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('SQL error /admin/lotteries:', err);
      return res.status(500).json({ ok: false, message: 'DB error' });
    }
    res.json({ ok: true, lotteries: rows });
  });
});

// ===================== ADMIN BULK EMAIL (Shopify customers) =====================
app.get('/admin/email', (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('Forbidden');
  res.send(`
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <div style="max-width:900px;margin:24px auto;font:16px/1.45 Arial,sans-serif;color:#222">
      <h2 style="margin:0 0 12px">Bulk Email (Shopify Customers)</h2>
      <form method="POST" action="/admin/email">
        <input type="hidden" name="pass" value="${(req.query.pass || '')}">
        <div style="margin:12px 0">
          <label>Segment (language / locale short):</label>
          <input name="segment" placeholder="e.g. en, de, fr (leave blank for all)" style="padding:8px;width:240px">
        </div>
        <div style="margin:12px 0">
          <label>Subject</label><br>
          <input name="subject" required style="width:100%;padding:10px" placeholder="Your subject">
        </div>
        <div style="margin:12px 0">
          <label>HTML</label><br>
          <textarea name="html" required rows="14" style="width:100%;padding:10px;font-family:monospace"></textarea>
          <small style="color:#666;display:block">We’ll append the unsubscribe footer + add a List-Unsubscribe header.</small>
        </div>
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin:12px 0">
          <label>Max recipients (this run):
            <input type="number" name="limit" value="500" min="1" max="10000" style="width:120px;padding:8px">
          </label>
          <label>Start after customer ID:
            <input type="number" name="since_id" value="0" style="width:160px;padding:8px">
          </label>
          <label><input type="checkbox" name="dry" checked> Dry run (preview only)</label>
          <label>Test to (optional email):
            <input type="email" name="test_to" placeholder="you@example.com" style="width:220px;padding:8px">
          </label>
        </div>
        <button type="submit" style="padding:10px 16px;background:#111;color:#fff;border:0;border-radius:6px">Send</button>
      </form>
    </div>
  `);
});

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// Generic fetch with 429-aware retries and small global pacing
async function shopifyFetchWithRetry(url, opts = {}, { maxRetries = 6 } = {}) {
  const f = await ensureFetch();
  let attempt = 0;

  while (true) {
    // pace to ~1.7 req/sec (cushion under 2/sec)
    if (attempt > 0) await sleep(200); else await sleep(600);

    const r = await f(url, opts);

    // Happy path
    if (r.status !== 429) return r;

    // 429: honor Retry-After or backoff
    attempt++;
    if (attempt > maxRetries) return r;

    const retryAfter = Number(r.headers.get('Retry-After')) || 1;
    await sleep(Math.min(5000, retryAfter * 1000 * attempt)); // exponential-ish
  }
}
async function fetchShopifyCustomers({ limit = 250, since_id = 0 } = {}) {
  const shop  = process.env.SHOPIFY_STORE;
  const token = process.env.SHOPIFY_ADMIN_API_KEY;
  if (!shop || !token) throw new Error('SHOPIFY env missing');

  let url = `https://${shop}/admin/api/2024-07/customers.json?limit=${Math.min(+limit || 250, 250)}&since_id=${since_id}`;

  const r = await shopifyFetchWithRetry(url, {
    method: 'GET',
    headers: {
      'X-Shopify-Access-Token': token,
      'Accept': 'application/json'
    }
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => '');
    throw new Error(`Shopify customers fetch failed: ${r.status} ${txt}`);
  }

  // read call-limit header (optional: log/slow further if near ceiling)
  const callLim = r.headers.get('X-Shopify-Shop-Api-Call-Limit'); // e.g. "1/40"
  if (callLim) {
    // Optional: parse and add extra sleep if near the bucket limit
  }

  const data = await r.json();
  return Array.isArray(data.customers) ? data.customers : [];
}
app.post('/admin/email', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(403).send('Forbidden');

    const subject = String(req.body.subject || '').trim();
    const html = String(req.body.html || '');
    let segment = String(req.body.segment || '').trim().toLowerCase().replace('_','-');
    const dryRun = !!req.body.dry;
    const limit = Math.max(1, Math.min(10000, Number(req.body.limit || 500)));
    let since_id = Number(req.body.since_id || 0) || 0;
    const testTo = String(req.body.test_to || '').trim();

    if (!subject || !html) return res.status(400).send('Missing subject or html');

    if (testTo) {
      const email = normEmail(testTo);
      await mailer.sendMail({
        from: process.env.FROM_EMAIL || process.env.EMAIL_USER,
        to: email,
        subject,
        html: withUnsubFooter(html, email),
        headers: { 'List-Unsubscribe': listUnsubHeader(email) }
      });
    }

    const toSend = [];
    while (toSend.length < limit) {
      const batch = await fetchShopifyCustomers({ limit: Math.min(250, limit - toSend.length), since_id });
      if (!batch.length) break;
      since_id = batch[batch.length - 1].id;
      await sleep(600); // ~0.6s cushion between Shopify API pages
      for (const c of batch) {
        const email = normEmail(c.email);
        if (!email) continue;

        // Normalize customer.locale
        const rawLocale = String(c.locale || '').trim();
        const locale = rawLocale.toLowerCase().replace('_', '-'); // e.g. "en-gb"
        const lang = (locale.split('-')[0] || '').trim();         // e.g. "en"

        // Normalize tags (Shopify REST gives comma-separated string)
        const tags = String(c.tags || '')
          .split(',')
          .map(s => s.trim())
          .filter(Boolean)
          .map(t => t.toLowerCase().replace('_', '-'));

        // Pull language from tags: prefer "lang-en"/"lang_en" (now normalized to lang-en), else bare "en"
        let langFromTags = '';
        const taggedLang = tags.find(t => /^lang-[a-z]{2}$/i.test(t));
        if (taggedLang) langFromTags = taggedLang.replace(/^lang-/, '');
        if (!langFromTags) {
          const bare = tags.find(t => /^[a-z]{2}$/i.test(t));
          if (bare) langFromTags = bare;
        }

        // accept things like en-gb, en-sti, en-us-east, etc.
        const fullLocalesFromTags = tags.filter(t => /^[a-z]{2}-[a-z0-9-]{2,}$/i.test(t));
        const baseFromFullTags = fullLocalesFromTags.map(t => t.slice(0, 2)); // ["en", "pt", ...]

        // Build a set of all candidates that should satisfy the segment
        const candidates = new Set(
          [lang, locale, langFromTags, ...fullLocalesFromTags, ...baseFromFullTags, ...tags].filter(Boolean)
        );

        // Apply segment filter:
        // - segment "en" matches "en", "en-gb", "en-us", tags "en"/"lang-en"/"en-gb"
        // - segment "en-gb" matches only "en-gb" (or tag "en-gb")
        if (segment && !candidates.has(segment)) continue;

        // Choose an effective locale to record/preview
        const effective =
          locale ||
          (fullLocalesFromTags[0] || '') ||
          lang ||
          (langFromTags || '') ||
          'en';

        toSend.push({ id: c.id, email, locale: effective });
        if (toSend.length >= limit) break;
      }
    }

    if (dryRun) {
      return res.send(`
        <div style="font:14px Arial,sans-serif">
          <h3>Dry run — would send to ${toSend.length} customers</h3>
          <p>Next since_id to continue: <code>${since_id}</code></p>
          <pre style="white-space:pre-wrap">${toSend.slice(0, 50).map(x => `${x.id}  ${x.email}  (${x.locale})`).join('\n')}${toSend.length>50?'\n…':''}</pre>
        </div>
      `);
    }

    let sent = 0, skipped = 0, failed = 0;
    for (const cust of toSend) {
      if (await isUnsubscribed(cust.email)) { skipped++; continue; }
      try {
        await mailer.sendMail({
          from: process.env.FROM_EMAIL || process.env.EMAIL_USER,
          to: cust.email,
          subject,
          html: withUnsubFooter(html, cust.email),
          headers: { 'List-Unsubscribe': listUnsubHeader(cust.email) }
        });
        sent++;
      } catch (e) {
        console.error('Bulk email error', cust.email, e);
        failed++;
      }
      await new Promise(r => setTimeout(r, 15));
    }

    res.send(`
      <div style="font:14px Arial,sans-serif">
        <h3>Bulk email done</h3>
        <p>Segment: <code>${segment || 'all'}</code></p>
        <p>Sent: ${sent}, Skipped (unsubscribed): ${skipped}, Failed: ${failed}</p>
        <p>Next since_id to continue: <code>${since_id}</code></p>
        <p><a href="/admin/email?pass=${encodeURIComponent(req.body.pass || '')}">Back</a></p>
      </div>
    `);
  } catch (err) {
    console.error('/admin/email error:', err);
    res.status(500).send('Server error');
  }
});

// === Admin UI to create/list campaigns ==============================
// Create campaign form
app.get('/admin/campaign/new', (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('Forbidden');
  res.send(`
    <meta charset="utf-8">
    <div style="max-width:900px;margin:24px auto;font:16px Arial">
      <h2>Create email campaign</h2>
      <form method="POST" action="/admin/campaign/create">
        <input type="hidden" name="pass" value="${(req.query.pass || '')}">
        <label>Name</label><br>
        <input name="name" style="width:100%;padding:8px" placeholder="October UK promo"><br><br>

        <label>Segment (e.g. en-gb; blank = all)</label><br>
        <input name="segment" style="width:240px;padding:8px" value=""><br><br>

        <label>Per-hour send limit</label><br>
        <input type="number" name="per_hour_limit" value="500" min="1" max="5000" style="width:160px;padding:8px"><br><br>

        <label>Total cap (safety)</label><br>
        <input type="number" name="total_cap" value="50000" min="1" max="5000000" style="width:160px;padding:8px"><br><br>

        <label>Subject</label><br>
        <input name="subject" required style="width:100%;padding:8px"><br><br>

        <label>HTML</label><br>
        <textarea name="html" required rows="12" style="width:100%;padding:8px;font-family:monospace"></textarea><br><br>

        <button type="submit" style="padding:10px 16px;background:#111;color:#fff;border:0;border-radius:6px">Create</button>
      </form>
    </div>
  `);
});

// Create campaign handler
app.post('/admin/campaign/create', (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('Forbidden');
  const name = String(req.body.name || '').trim();
  const subject = String(req.body.subject || '').trim();
  const html = String(req.body.html || '').trim();
  let segment = String(req.body.segment || '').trim().toLowerCase().replace('_','-'); // e.g. en-gb
  const perHour = Math.max(1, Math.min(5000, Number(req.body.per_hour_limit || 500)));
  const totalCap = Math.max(1, Math.min(5_000_000, Number(req.body.total_cap || 50_000)));

  if (!subject || !html) return res.status(400).send('Missing subject/html');

  db.run(`
    INSERT INTO email_campaigns (name, subject, html, segment, per_hour_limit, total_cap, status)
    VALUES (?, ?, ?, ?, ?, ?, 'active')
  `, [name, subject, html, segment || null, perHour, totalCap], function (err) {
    if (err) {
      console.error('campaign create error', err);
      return res.status(500).send('DB error');
    }
    res.send(`
      <div style="font:16px Arial;padding:20px">
        <p>Campaign created with id <b>${this.lastID}</b>.</p>
        <p>Schedule hourly runner URL (GET):<br>
        <code>/admin/campaign/run?id=${this.lastID}&pass=${encodeURIComponent(req.body.pass || '')}</code></p>
        <p><a href="/admin/campaigns?pass=${encodeURIComponent(req.body.pass || '')}">View campaigns</a></p>
      </div>
    `);
  });
});

// List campaigns
app.get('/admin/campaigns', (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('Forbidden');
  db.all(`SELECT * FROM email_campaigns ORDER BY id DESC LIMIT 100`, [], (err, rows) => {
    if (err) return res.status(500).send('DB error');
    res.send(`<meta charset="utf-8"><pre>${JSON.stringify(rows, null, 2)}</pre>`);
  });
});

// === Hourly campaign runner ========================================
app.get('/admin/campaign/run', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('Forbidden');
  const id = Number(req.query.id || 0);
  if (!id) return res.status(400).send('Missing id');

  // Load campaign
  db.get(`SELECT * FROM email_campaigns WHERE id = ?`, [id], async (err, camp) => {
    if (err) return res.status(500).send('DB error');
    if (!camp) return res.status(404).send('Campaign not found');
    if (camp.status !== 'active') return res.status(200).send(`Campaign status is ${camp.status}; nothing to do.`);

    // Lock (avoid overlapping runs)
    const gotLock = await acquireCampaignLock(id);
    if (!gotLock) return res.status(200).send('Runner already in progress (lock held).');

    const perHour = Number(camp.per_hour_limit || 500);
    const totalCap = Number(camp.total_cap || 100000);
    let since = Number(camp.since_id || 0) || 0;
    let sent = 0, failed = 0, skipped = 0;

    try {
      // Build slice to send (<= perHour and <= remaining cap)
      const toSend = [];
      while (toSend.length < perHour && (camp.sent_count + toSend.length) < totalCap) {
        const batch = await fetchShopifyCustomers({ limit: Math.min(250, perHour - toSend.length), since_id: since });
        if (!batch.length) break;
        since = batch[batch.length - 1].id;

        for (const c of batch) {
          if (!c.email) continue;
          const email = normEmail(c.email);

          // --- segmentation logic (same idea as /admin/email) ---
          const rawLocale = String(c.locale || '').trim();
          const locale = rawLocale.toLowerCase().replace('_', '-');    // e.g. "en-gb"
          const lang = (locale.split('-')[0] || '').trim();            // "en"
          const tags = String(c.tags || '')
            .split(',')
            .map(s => s.trim())
            .filter(Boolean)
            .map(t => t.toLowerCase().replace('_', '-'));

          let langFromTags = '';
          const taggedLang = tags.find(t => /^lang-[a-z]{2}$/i.test(t));
          if (taggedLang) langFromTags = taggedLang.replace(/^lang-/, '');
          if (!langFromTags) {
            const bare = tags.find(t => /^[a-z]{2}$/i.test(t));
            if (bare) langFromTags = bare;
          }
          const fullLocalesFromTags = tags.filter(t => /^[a-z]{2}-[a-z0-9-]{2,}$/i.test(t));
          const baseFromFullTags = fullLocalesFromTags.map(t => t.slice(0, 2));

          const candidates = new Set([lang, locale, langFromTags, ...fullLocalesFromTags, ...baseFromFullTags, ...tags].filter(Boolean));
          const segment = (camp.segment || '').trim().toLowerCase();
          if (segment && !candidates.has(segment)) continue;

          toSend.push({ id: c.id, email });
          if (toSend.length >= perHour || (camp.sent_count + toSend.length) >= totalCap) break;
        }
      }

      // Send this hour's slice
      for (const cust of toSend) {
        if (await isUnsubscribed(cust.email)) { skipped++; continue; }
        try {
          await mailer.sendMail({
            from: process.env.FROM_EMAIL || process.env.EMAIL_USER,
            to: cust.email,
            subject: camp.subject,
            html: withUnsubFooter(camp.html, cust.email),
            headers: { 'List-Unsubscribe': listUnsubHeader(cust.email) }
          });
          sent++;
        } catch (e) {
          console.error('Campaign send error', cust.email, e);
          failed++;
        }
        // gentle throttle (ESP-friendly)
        await new Promise(r => setTimeout(r, 20));
      }

      // Progress + status
      const newSent = (camp.sent_count || 0) + sent;
      const newFailed = (camp.failed_count || 0) + failed;
      const newSkipped = (camp.skipped_count || 0) + skipped;

      let newStatus = 'active';
      if (newSent >= totalCap) newStatus = 'done';
      if (sent === 0 && failed === 0 && skipped === 0) newStatus = 'done'; // nothing more to send

      db.run(`
        UPDATE email_campaigns
        SET sent_count = ?, failed_count = ?, skipped_count = ?, since_id = ?, status = ?, last_run_at = datetime('now'), lock_until = NULL
        WHERE id = ?
      `, [newSent, newFailed, newSkipped, since, newStatus, id], (uErr) => {
        if (uErr) console.error('Campaign update error', uErr);
      });

      res.json({
        ok: true,
        id,
        attempted: toSend.length,
        sent, failed, skipped,
        since_id: since,
        total_sent: newSent,
        status: newStatus
      });
    } catch (e) {
      console.error('campaign run error', e);
      // release lock on error too
      releaseCampaignLock(id);
      return res.status(500).json({ ok: false, error: 'run failed' });
    }
  });
});

// Optional convenience redirect so /campaign/new works too
app.get('/campaign/new', (req, res) => {
  const pass = req.query.pass || '';
  res.redirect(`/admin/campaign/new?pass=${encodeURIComponent(pass)}`);
});

// --- PUBLIC: list current active lotteries ---
app.get('/lottery/current', (req, res) => {
  const sql = `
    SELECT productId, name, endAt
    FROM products
    WHERE endAt IS NULL OR datetime(endAt) > datetime('now')
    ORDER BY CASE WHEN endAt IS NULL OR endAt = '' THEN 1 ELSE 0 END, endAt
    LIMIT 10
  `;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ ok: false, message: 'DB error' });
    res.json({ ok: true, lotteries: rows });
  });
});

// --- PUBLIC: fetch only one active lottery ---
app.get('/lottery/current/one', (req, res) => {
  const sql = `
    SELECT productId, name, endAt
    FROM products
    WHERE endAt IS NULL OR datetime(endAt) > datetime('now')
    ORDER BY CASE WHEN endAt IS NULL OR endAt = '' THEN 1 ELSE 0 END, endAt
    LIMIT 1
  `;
  db.get(sql, [], (err, row) => {
    if (err) return res.status(500).json({ ok: false, message: 'DB error' });
    res.json({ ok: true, lottery: row || null });
  });
});

// --- PUBLIC: get entry count for a product ---
app.get('/lottery/count/:productId', (req, res) => {
  const productId = req.params.productId;
  db.get(`SELECT COUNT(*) AS c FROM entries WHERE productId = ?`, [productId], (err, row) => {
    if (err) {
      console.error('SQL error /lottery/count:', err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true, totalEntries: row?.c || 0 });
  });
});

// ---------- Health checks ----------
app.get('/', (_req, res) => res.json({ ok: true, service: 'lottery+bis', version: 1 }));
app.get('/health', (_req, res) => res.json({ ok: true, service: 'lottery+bis', version: 1 }));

// ---------- Start server ----------
app.listen(port, host, () => {
  console.log(`✅ Lottery/BIS server listening on ${host}:${port}`);
});

