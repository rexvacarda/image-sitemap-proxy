import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import { URL } from "url";

const app = express();

/* ========= CONFIG via ENV =========
Required (OAuth app installed per shop):
  APP_API_KEY        -> Client ID (Partners)
  APP_API_SECRET     -> API secret (also used for App Proxy HMAC)
  HOST               -> Public base URL of this server, e.g. https://image-sitemap-proxy.onrender.com
  SCOPES             -> e.g. read_products,read_collections

Optional:
  API_VERSION        -> Admin API version, default 2024-04 (or newer)
  CACHE_TTL_SECONDS  -> default 900 (15m)
  MAX_URLS_PER_FEED  -> default 5000
  DEFAULT_PER_PAGE   -> default 1000 (capped to MAX_URLS_PER_FEED)
=================================== */

const APP_API_KEY = process.env.APP_API_KEY || "";
const APP_API_SECRET = process.env.APP_API_SECRET || "";
const HOST = process.env.HOST || "";
const SCOPES = process.env.SCOPES || "read_products,read_collections";

const API_VERSION = process.env.API_VERSION || "2024-04";
const CACHE_TTL_SECONDS = Number(process.env.CACHE_TTL_SECONDS || 900);
const MAX_URLS_PER_FEED = Number(process.env.MAX_URLS_PER_FEED || 5000);
const DEFAULT_PER_PAGE = Math.min(Number(process.env.DEFAULT_PER_PAGE || 1000), MAX_URLS_PER_FEED);

// In-memory token store per shop (replace with Redis in production)
const tokenStore = new Map(); // shop => { accessToken, installedAt }

// Simple in-memory response cache
const responseCache = new Map(); // key => { body, expiresAt }

/* ========== Helpers ========== */

function cacheKey(parts) {
  return Object.entries(parts).map(([k,v]) => `${k}=${v}`).sort().join("|");
}

function setXmlHeaders(res) {
  res.set("Content-Type", "application/xml; charset=utf-8");
  res.set("Cache-Control", `public, max-age=${CACHE_TTL_SECONDS}`);
}

function x(s = "") {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function stripPort(host) {
  return (host || "").replace(/:.+$/, "");
}

function preferHostImageUrl(originalUrl, host) {
  try {
    const u = new URL(originalUrl);
    if (u.hostname !== "cdn.shopify.com") return originalUrl;
    const path = u.pathname;
    const idxProducts = path.indexOf("/products/");
    const idxFiles = path.indexOf("/files/");
    let rebuilt = null;
    if (idxProducts !== -1) rebuilt = `/cdn/shop${path.substring(idxProducts)}${u.search || ""}`;
    else if (idxFiles !== -1) rebuilt = `/cdn/shop${path.substring(idxFiles)}${u.search || ""}`;
    return rebuilt ? `https://${host}${rebuilt}` : originalUrl;
  } catch {
    return originalUrl;
  }
}

function pageUrlForProduct(host, handle, onlineStoreUrl) {
  const h = stripPort(host);
  if (onlineStoreUrl) return onlineStoreUrl.replace(/^https?:\/\/[^/]+/, `https://${h}`);
  return `https://${h}/products/${handle}`;
}

function pageUrlForCollection(host, handle) {
  const h = stripPort(host);
  return `https://${h}/collections/${handle}`;
}

function verifyProxyHmac(req) {
  const { signature, ...params } = req.query;
  if (!APP_API_SECRET || !signature) return false;
  const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join("");
  const digest = crypto.createHmac("sha256", APP_API_SECRET).update(sorted).digest("hex");
  return signature === digest;
}

/* ---------- Locale detection & mapping ---------- */
// Map host → primary locale used in Shopify translations
function localeFromHost(host) {
  const h = (host || "").toLowerCase();
  if (h.startsWith("smelltoimpress.fr")) return "fr";
  if (h.startsWith("smelltoimpress.it")) return "it";
  if (h.startsWith("smelltoimpress.jp")) return "ja"; // JA (not "jp")
  if (h.startsWith("ko.smelltoimpress.com")) return "ko";
  if (h.startsWith("ar.smelltoimpress.com")) return "ar";
  if (h.startsWith("iw.smelltoimpress.com")) return "he"; // Hebrew is "he"
  if (h.startsWith("smelltoimpress.nl")) return "nl";
  if (h.startsWith("smelltoimpress.ch")) return "de"; // assuming DE for CH
  if (h.startsWith("smelltoimpress.co.no")) return "nb"; // Norwegian Bokmål
  // default english
  return "en";
}

// Given a base like "fr", return candidates to try (e.g. fr-FR, fr)
function localeCandidates(base) {
  const b = (base || "en").toLowerCase();
  const regionByBase = { fr: "FR", it: "IT", nl: "NL", de: "DE", ar: "AR", he: "IL", ko: "KR", ja: "JP", nb: "NO", en: "US" };
  const region = regionByBase[b] || "US";
  // try exact base-region first, then base only
  const candidates = [`${b}-${region}`, b];
  // de-CH special-case if host is smelltoimpress.ch
  if (b === "de") candidates.unshift("de-CH");
  return Array.from(new Set(candidates));
}

/* ========== OAuth (public app) minimal flow ========== */
app.get("/auth", (req, res) => {
  const shop = String(req.query.shop || "");
  if (!shop || !shop.endsWith(".myshopify.com")) return res.status(400).send("Missing/invalid shop");
  const state = crypto.randomBytes(12).toString("hex");
  const redirectUri = `${HOST}/auth/callback`;
  const url = `https://${shop}/admin/oauth/authorize?client_id=${APP_API_KEY}` +
              `&scope=${encodeURIComponent(SCOPES)}` +
              `&redirect_uri=${encodeURIComponent(redirectUri)}` +
              `&state=${state}`;
  res.redirect(url);
});

app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code } = req.query;
    if (!shop || !code) return res.status(400).send("Missing shop/code");
    const tokenResp = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: APP_API_KEY, client_secret: APP_API_SECRET, code })
    });
    if (!tokenResp.ok) return res.status(400).send(`Token exchange failed: ${await tokenResp.text()}`);
    const json = await tokenResp.json();
    tokenStore.set(shop, { accessToken: json.access_token, installedAt: Date.now() });
    res.type("text/plain").send(
      `Installed for ${shop}. Token stored in memory. App Proxy: https://${stripPort(req.get("host"))}/apps/sitemaps/image.xml`
    );
  } catch (err) {
    console.error(err);
    res.status(500).send("OAuth error");
  }
});

/* ========== Admin API fetchers ========== */

async function shopifyGraphQL(shop, accessToken, query, variables = {}) {
  const resp = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
    method: "POST",
    headers: {
      "X-Shopify-Access-Token": accessToken,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query, variables }),
  });
  if (!resp.ok) throw new Error(`Admin API ${resp.status}: ${await resp.text()}`);
  return resp.json();
}

async function getAllProductsWithImages(shop, accessToken) {
  const query = `
    query Products($first:Int!, $after:String) {
      products(first:$first, after:$after, query:"status:active") {
        edges {
          cursor
          node {
            id
            title
            handle
            onlineStoreUrl
            updatedAt
            images(first:50) { edges { node { id url altText } } }
          }
        }
        pageInfo { hasNextPage }
      }
    }
  `;
  const all = [];
  let after = null, hasNext = true;
  while (hasNext) {
    const data = await shopifyGraphQL(shop, accessToken, query, { first: 100, after });
    const edges = data?.data?.products?.edges || [];
    for (const e of edges) all.push(e.node);
    hasNext = data?.data?.products?.pageInfo?.hasNextPage;
    after = edges.length ? edges[edges.length - 1].cursor : null;
  }
  return all;
}

async function getAllCollectionsWithImage(shop, accessToken) {
  const query = `
    query Collections($first:Int!, $after:String) {
      collections(first:$first, after:$after, query:"published_status:published") {
        edges {
          cursor
          node {
            id
            title
            handle
            updatedAt
            image { id url altText }
          }
        }
        pageInfo { hasNextPage }
      }
    }
  `;
  const all = [];
  let after = null, hasNext = true;
  while (hasNext) {
    const data = await shopifyGraphQL(shop, accessToken, query, { first: 200, after });
    const edges = data?.data?.collections?.edges || [];
    for (const e of edges) all.push(e.node);
    hasNext = data?.data?.collections?.pageInfo?.hasNextPage;
    after = edges.length ? edges[edges.length - 1].cursor : null;
  }
  return all;
}

/* ---------- Translations hydration using translatableResource ---------- */

async function hydrateProductTranslations(shop, token, products, localeBase) {
  const tryLocs = localeCandidates(localeBase);
  const q = `
    query TR($rid: ID!, $loc: String!) {
      translatableResource(resourceId: $rid) {
        resourceId
        translations(locale: $loc) {
          key
          value
        }
        ... on Product {
          images(first: 50) {
            edges {
              node {
                id
                translations(locale: $loc) { key value } # key "alt"
              }
            }
          }
        }
      }
    }
  `;

  for (const p of products) {
    for (const loc of tryLocs) {
      try {
        const data = await shopifyGraphQL(shop, token, q, { rid: p.id, loc });
        const tr = data?.data?.translatableResource;
        if (!tr) continue;
        // Product title
        const tTitle = tr.translations?.find(t => t.key === "title")?.value;
        if (tTitle) p.title = tTitle;
        // Images alt
        const imgEdges = tr.images?.edges || [];
        const altById = new Map();
        for (const e of imgEdges) {
          const tAlt = e.node?.translations?.find(t => t.key === "alt")?.value;
          if (tAlt) altById.set(e.node.id, tAlt);
        }
        for (const e of p.images?.edges || []) {
          const alt = altById.get(e.node.id);
          if (alt) e.node.altText = alt;
        }
        break; // success for this locale
      } catch {
        // try next candidate
      }
    }
  }
}

async function hydrateCollectionTranslations(shop, token, collections, localeBase) {
  const tryLocs = localeCandidates(localeBase);
  const q = `
    query TRC($rid: ID!, $loc: String!) {
      translatableResource(resourceId: $rid) {
        resourceId
        translations(locale: $loc) { key value }  # title, body_html, etc.
        ... on Collection {
          image {
            id
            translations(locale: $loc) { key value } # alt
          }
        }
      }
    }
  `;

  for (const c of collections) {
    for (const loc of tryLocs) {
      try {
        const data = await shopifyGraphQL(shop, token, q, { rid: c.id, loc });
        const tr = data?.data?.translatableResource;
        if (!tr) continue;
        const tTitle = tr.translations?.find(t => t.key === "title")?.value;
        if (tTitle) c.title = tTitle;
        const alt = tr.image?.translations?.find(t => t.key === "alt")?.value;
        if (alt && c.image) c.image.altText = alt;
        break;
      } catch {
        // try next candidate
      }
    }
  }
}

/* ========== XML builders ========== */

function buildImageNode(loc, title, caption) {
  return `
        <image:image>
          <image:loc>${x(loc)}</image:loc>
          ${title ? `<image:title>${x(title)}</image:title>` : ""}
          ${caption ? `<image:caption>${x(caption)}</image:caption>` : ""}
        </image:image>`;
}

function buildUrlNode(pageLoc, lastmodISO, imageNodes) {
  return `<url>
      <loc>${x(pageLoc)}</loc>
      ${lastmodISO ? `<lastmod>${x(lastmodISO)}</lastmod>` : ""}${imageNodes.join("")}
    </url>`;
}

/* ========== Main proxy endpoints ========== */
/*
  Via App Proxy:
    /apps/sitemaps/image.xml
    /apps/sitemaps/image-index.xml

  Query params:
    - shop=STORE.myshopify.com           (required by proxy signature)
    - type=products|collections|all      (default: all)
    - page=1..N                          (default: 1)
    - per_page=number                    (default: env DEFAULT_PER_PAGE, max MAX_URLS_PER_FEED)
    - locale=fr                          (override host-detected locale)
    - captions=0|1                       (default: 1)
    - prefer_host=0|1                    (default: 1)
*/
app.get("/image.xml", async (req, res) => {
  try {
    if (!verifyProxyHmac(req)) return res.status(401).send("Invalid signature");

    const forwardedHost = req.get("x-forwarded-host") || req.get("host");
    const host = stripPort(forwardedHost);
    const shop = String(req.query.shop || "");
    const page = Math.max(parseInt(req.query.page || "1", 10), 1);
    const perPageRaw = Math.max(parseInt(req.query.per_page || String(DEFAULT_PER_PAGE), 10), 1);
    const perPage = Math.min(perPageRaw, MAX_URLS_PER_FEED);
    const type = (req.query.type || "all").toLowerCase();
    const includeCaptions = String(req.query.captions || "1") === "1";
    const preferHost = String(req.query.prefer_host || "1") === "1";
    const overrideLocale = (req.query.locale || "").toString().trim();
    const localeBase = overrideLocale || localeFromHost(host); // base locale like fr, it, ja, he, etc.

    // Cache key
    const key = cacheKey({ route: "image.xml", host, shop, page, perPage, type, includeCaptions, preferHost, localeBase });
    const hit = responseCache.get(key);
    const now = Date.now();
    if (hit && hit.expiresAt > now) {
      setXmlHeaders(res);
      return res.status(200).send(hit.body);
    }

    const tokenEntry = tokenStore.get(shop);
    if (!tokenEntry?.accessToken) {
      return res.status(403).type("text/plain").send(`App not installed for ${shop}. Visit ${HOST}/auth?shop=${shop}`);
    }

    const nodes = [];

    if (type === "products" || type === "all") {
      const products = await getAllProductsWithImages(shop, tokenEntry.accessToken);
      // hydrate translations for products + image alts
      await hydrateProductTranslations(shop, tokenEntry.accessToken, products, localeBase);

      for (const p of products) {
        const pageUrl = pageUrlForProduct(host, p.handle, p.onlineStoreUrl);
        const images = (p.images?.edges || []).map(e => e.node);
        if (!images.length) continue;

        const imageNodes = images.map(img => {
          const imgUrl = preferHost ? preferHostImageUrl(img.url, host) : img.url;
          const title = img.altText || p.title || ""; // prefer altText if localized, else title
          const caption = includeCaptions && img.altText ? img.altText : (includeCaptions ? p.title || "" : "");
          return buildImageNode(imgUrl, title, caption);
        });

        nodes.push({ lastmod: p.updatedAt, xml: buildUrlNode(pageUrl, p.updatedAt, imageNodes) });
      }
    }

    if (type === "collections" || type === "all") {
      const collections = await getAllCollectionsWithImage(shop, tokenEntry.accessToken);
      // hydrate translations for collections + collection image alt
      await hydrateCollectionTranslations(shop, tokenEntry.accessToken, collections, localeBase);

      for (const c of collections) {
        if (!c.image?.url) continue;
        const pageUrl = pageUrlForCollection(host, c.handle);
        const imgUrl = preferHost ? preferHostImageUrl(c.image.url, host) : c.image.url;

        const title = c.image.altText || c.title || ""; // prefer localized alt if exists, else localized title
        const caption = includeCaptions && c.image.altText ? c.image.altText : (includeCaptions ? c.title || "" : "");
        const imageNodes = [buildImageNode(imgUrl, title, caption)];

        nodes.push({ lastmod: c.updatedAt, xml: buildUrlNode(pageUrl, c.updatedAt, imageNodes) });
      }
    }

    // Newest first, paginate
    nodes.sort((a, b) => (a.lastmod < b.lastmod ? 1 : -1));
    const start = (page - 1) * perPage;
    const slice = nodes.slice(start, start + perPage).map(n => n.xml);

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
${slice.join("\n")}
</urlset>`;

    responseCache.set(key, { body: xml, expiresAt: now + CACHE_TTL_SECONDS * 1000 });
    setXmlHeaders(res);
    return res.status(200).send(xml);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Sitemap generation error");
  }
});

// sanity
app.get("/echo", (_req, res) => res.type("text/plain").send("echo ok"));

app.get("/image-index.xml", (req, res) => {
  const forwardedHost = req.get("x-forwarded-host") || req.get("host");
  const host = stripPort(forwardedHost);
  const shop = String(req.query.shop || "");
  const pages = Number(req.query.pages || 5);
  const type = String(req.query.type || "all");
  const perPage = Number(req.query.per_page || DEFAULT_PER_PAGE);
  const locale = String(req.query.locale || "");

  const urls = Array.from({ length: pages }, (_, i) => i + 1).map(
    (n) => `<sitemap><loc>https://${host}/apps/sitemaps/image.xml?shop=${shop}&type=${encodeURIComponent(type)}&page=${n}&per_page=${perPage}${locale ? `&locale=${encodeURIComponent(locale)}` : ""}</loc></sitemap>`
  );

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join("\n")}
</sitemapindex>`;

  setXmlHeaders(res);
  return res.status(200).send(xml);
});

app.get("/health", (_req, res) => res.type("text/plain").send("ok"));
app.get("/", (_req, res) => {
  res.type("text/plain").send("Image Sitemap Proxy is running. Use /health, /echo, or call via Shopify App Proxy at /apps/sitemaps/image.xml");
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Image sitemap proxy on :${port}`));
