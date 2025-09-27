import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();

/* ========= CONFIG via ENV =========
Required (OAuth app installed per shop):
  APP_API_KEY        -> Client ID from Partner app (used by OAuth routes)
  APP_API_SECRET     -> API secret key (also App Proxy shared secret for HMAC)
  HOST               -> Public base URL of this server, e.g. https://image-sitemap-proxy.onrender.com
  SCOPES             -> e.g. read_products,read_collections

Optional:
  API_VERSION        -> Admin API version, default 2024-04
  CACHE_TTL_SECONDS  -> default 900 (15m)
  MAX_URLS_PER_FEED  -> default 5000 (keep < 50k)
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

// In-memory token store per shop (replace with Redis for production)
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
  // Shopify App Proxy sends all query params plus `signature` (hex HMAC-SHA256)
  const { signature, ...params } = req.query;
  if (!APP_API_SECRET || !signature) return false;
  const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join("");
  const digest = crypto.createHmac("sha256", APP_API_SECRET).update(sorted).digest("hex");
  return signature === digest;
}

/* ========== OAuth (public app) minimal flow ========== */
app.get("/auth", (req, res) => {
  const shop = String(req.query.shop || "");
  if (!shop || !shop.endsWith(".myshopify.com")) {
    return res.status(400).send("Missing/invalid shop");
  }
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
      body: JSON.stringify({
        client_id: APP_API_KEY,
        client_secret: APP_API_SECRET,
        code
      })
    });
    if (!tokenResp.ok) {
      const t = await tokenResp.text();
      return res.status(400).send(`Token exchange failed: ${t}`);
    }
    const json = await tokenResp.json();
    tokenStore.set(shop, { accessToken: json.access_token, installedAt: Date.now() });
    res
      .type("text/plain")
      .send(`Installed for ${shop}. Token stored in memory. You can now hit your App Proxy: https://${stripPort(req.get("host"))}/apps/sitemaps/image.xml`);
  } catch (err) {
    console.error(err);
    res.status(500).send("OAuth error");
  }
});

/* ========== Admin API fetchers (use per-shop token) ========== */

async function shopifyGraphQL(shop, accessToken, query, variables = {}) {
  const resp = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
    method: "POST",
    headers: {
      "X-Shopify-Access-Token": accessToken,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query, variables }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Admin API ${resp.status}: ${text}`);
  }
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
            images(first:50) {
              edges { node { url altText } }
            }
          }
        }
        pageInfo { hasNextPage }
      }
    }
  `;
  const all = [];
  let after = null;
  let hasNext = true;
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
            image { url altText }
          }
        }
        pageInfo { hasNextPage }
      }
    }
  `;
  const all = [];
  let after = null;
  let hasNext = true;
  while (hasNext) {
    const data = await shopifyGraphQL(shop, accessToken, query, { first: 200, after });
    const edges = data?.data?.collections?.edges || [];
    for (const e of edges) all.push(e.node);
    hasNext = data?.data?.collections?.pageInfo?.hasNextPage;
    after = edges.length ? edges[edges.length - 1].cursor : null;
  }
  return all;
}

/* ========== XML builders (strict: only existing alt text, no caption) ========== */

function buildImageNode(loc, altText) {
  return `
    <image:image>
      <image:loc>${x(loc)}</image:loc>
      ${altText ? `<image:title>${x(altText)}</image:title>` : ""}
    </image:image>`;
}

function buildUrlNode(pageLoc, lastmodISO, imageNodes) {
  return `
  <url>
    <loc>${x(pageLoc)}</loc>
    ${lastmodISO ? `<lastmod>${x(lastmodISO)}</lastmod>` : ""}
    ${imageNodes.join("")}
  </url>`;
}

/* ========== Main proxy endpoints ========== */
/*
  Proxied by Shopify to:
    /apps/sitemaps/image.xml         -> GET /image.xml (this server)
    /apps/sitemaps/image-index.xml   -> GET /image-index.xml

  Query params (optional):
    - type=products|collections|all  (default: all)
    - page=1..N                      (default: 1)
    - per_page=number                (default: env DEFAULT_PER_PAGE, max MAX_URLS_PER_FEED)
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

    // cache
    const key = cacheKey({ route: "image.xml", host, shop, page, perPage, type });
    const hit = responseCache.get(key);
    const now = Date.now();
    if (hit && hit.expiresAt > now) {
      setXmlHeaders(res);
      return res.status(200).send(hit.body);
    }

    const tokenEntry = tokenStore.get(shop);
    if (!tokenEntry?.accessToken) {
      return res
        .status(403)
        .type("text/plain")
        .send(`App not installed for ${shop}. Visit ${HOST}/auth?shop=${shop}`);
    }

    const nodes = [];

    if (type === "products" || type === "all") {
      const products = await getAllProductsWithImages(shop, tokenEntry.accessToken);
      for (const p of products) {
        const pageUrl = pageUrlForProduct(host, p.handle, p.onlineStoreUrl);
        const images = (p.images?.edges || []).map((e) => e.node);
        if (!images.length) continue;
        const imageNodes = images.map((img) => buildImageNode(img.url, img.altText)); // strict alt only
        nodes.push({ lastmod: p.updatedAt, xml: buildUrlNode(pageUrl, p.updatedAt, imageNodes) });
      }
    }

    if (type === "collections" || type === "all") {
      const collections = await getAllCollectionsWithImage(shop, tokenEntry.accessToken);
      for (const c of collections) {
        if (!c.image?.url) continue;
        const pageUrl = pageUrlForCollection(host, c.handle);
        const imageNodes = [ buildImageNode(c.image.url, c.image.altText) ]; // strict alt only
        nodes.push({ lastmod: c.updatedAt, xml: buildUrlNode(pageUrl, c.updatedAt, imageNodes) });
      }
    }

    // Order newest first
    nodes.sort((a, b) => (a.lastmod < b.lastmod ? 1 : -1));

    // Pagination
    const start = (page - 1) * perPage;
    const end = start + perPage;
    const slice = nodes.slice(start, end).map(n => n.xml);

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset
  xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
  xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
${slice.join("\n")}
</urlset>`;

    // Cache store
    responseCache.set(key, { body: xml, expiresAt: now + CACHE_TTL_SECONDS * 1000 });

    setXmlHeaders(res);
    return res.status(200).send(xml);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Sitemap generation error");
  }
});

// Sanity check
app.get("/echo", (_req, res) => res.type("text/plain").send("echo ok"));

/* Optional: simple index that links to a few pages for all/type */
app.get("/image-index.xml", (req, res) => {
  const forwardedHost = req.get("x-forwarded-host") || req.get("host");
  const host = stripPort(forwardedHost);
  const shop = String(req.query.shop || "");
  const pages = Number(req.query.pages || 5);
  const type = String(req.query.type || "all");
  const perPage = Number(req.query.per_page || DEFAULT_PER_PAGE);

  const urls = Array.from({ length: pages }, (_, i) => i + 1).map(
    (n) => `<sitemap><loc>https://${host}/apps/sitemaps/image.xml?shop=${shop}&type=${encodeURIComponent(type)}&page=${n}&per_page=${perPage}</loc></sitemap>`
  );

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join("\n")}
</sitemapindex>`;

  setXmlHeaders(res);
  return res.status(200).send(xml);
});

/* Health & root */
app.get("/health", (_req, res) => res.type("text/plain").send("ok"));
app.get("/", (_req, res) => {
  res
    .type("text/plain")
    .send("Image Sitemap Proxy is running. Use /health, /echo, or call via Shopify App Proxy at /apps/sitemaps/image.xml");
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Image sitemap proxy on :${port}`));
