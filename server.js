import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();

/* ========= CONFIG via ENV =========
REQUIRED (Partner/Dev app with OAuth):
  APP_API_KEY         -> From Shopify app "API credentials" (Client ID)
  APP_API_SECRET      -> From Shopify app "API credentials" (Client secret)
  SCOPES              -> e.g. "read_products,read_collections"
  HOST                -> Your public app URL (https://image-sitemap-proxy.onrender.com)

OPTIONAL:
  API_VERSION         -> e.g. 2024-04 (default)
  CACHE_TTL_SECONDS   -> e.g. 3600 (1h)
  MAX_URLS_PER_FEED   -> e.g. 45000 (keep < 50k)
=================================== */

const APP_API_KEY = process.env.APP_API_KEY;
const APP_API_SECRET = process.env.APP_API_SECRET;
const SCOPES = process.env.SCOPES || "read_products,read_collections";
const HOST = process.env.HOST; // e.g., https://image-sitemap-proxy.onrender.com
const API_VERSION = process.env.API_VERSION || "2024-04";
const CACHE_TTL_SECONDS = Number(process.env.CACHE_TTL_SECONDS || 3600);
const MAX_URLS_PER_FEED = Number(process.env.MAX_URLS_PER_FEED || 45000);

if (!APP_API_KEY || !APP_API_SECRET || !HOST) {
  console.warn("[startup] Missing APP_API_KEY / APP_API_SECRET / HOST envs.");
}

/** ======================================================================
 * Simple in-memory token store (shop -> access_token).
 * Replace with Redis/DB for production multi-instance reliability.
 * ====================================================================== */
const tokenStore = new Map();

/* ========== Helpers ========== */

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

/** =====================================================
 * App Proxy signature verification
 * Shopify App Proxy adds ?shop & ?signature.
 * The signature is HMAC-SHA256 of the sorted query string
 * without the signature itself, using APP_API_SECRET.
 * ===================================================== */
function verifyAppProxy(req) {
  const { signature, ...params } = req.query;
  if (!signature) return false;
  const sorted = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join("");
  const digest = crypto.createHmac("sha256", APP_API_SECRET).update(sorted).digest("hex");
  return signature === digest;
}

/** =============================================
 * OAuth helpers
 * ============================================= */
function buildInstallUrl(shop) {
  const redirectUri = `${HOST.replace(/\/$/, "")}/auth/callback`;
  const state = crypto.randomBytes(16).toString("hex");
  const url = new URL(`https://${shop}/admin/oauth/authorize`);
  url.searchParams.set("client_id", APP_API_KEY);
  url.searchParams.set("scope", SCOPES);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);
  return { url: url.toString(), state };
}

function verifyHmacFromQuery(query) {
  // For OAuth callback (uses 'hmac' param)
  const { hmac, signature, ...rest } = query;
  if (!hmac) return false;
  const message = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${rest[k]}`)
    .join("&");
  const digest = crypto.createHmac("sha256", APP_API_SECRET).update(message).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(hmac, "utf8"));
}

/* ========== Shopify Admin GraphQL fetchers (per-shop access token) ========== */

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
            title
            handle
            onlineStoreUrl
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
            title
            handle
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

/* ========== XML builders ========== */

function buildImageNode(loc, title) {
  return `
    <image:image>
      <image:loc>${x(loc)}</image:loc>
      ${title ? `<image:title>${x(title)}</image:title>` : ""}
    </image:image>`;
}

function buildUrlNode(pageLoc, imageNodes) {
  return `
  <url>
    <loc>${x(pageLoc)}</loc>
    ${imageNodes.join("")}
  </url>`;
}

/* ========== OAuth routes ========== */

/**
 * Kick off OAuth for a shop
 * GET /auth?shop=smelltoimpress.myshopify.com
 */
app.get("/auth", (req, res) => {
  const shop = String(req.query.shop || "");
  if (!shop.endsWith(".myshopify.com")) {
    return res.status(400).send("Missing or invalid ?shop=myshop.myshopify.com");
  }
  const { url } = buildInstallUrl(shop);
  return res.redirect(url);
});

/**
 * OAuth callback
 * Shopify redirects to: HOST/auth/callback?shop=...&hmac=...&code=...
 */
app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code } = req.query;
    if (!verifyHmacFromQuery(req.query)) {
      return res.status(400).send("HMAC verification failed");
    }
    if (!shop || !code) {
      return res.status(400).send("Missing shop or code");
    }

    // Exchange code for access token
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
      throw new Error(`Access token error ${tokenResp.status}: ${t}`);
    }
    const tokenJson = await tokenResp.json();
    const accessToken = tokenJson.access_token;

    tokenStore.set(String(shop), String(accessToken));

    return res
      .status(200)
      .type("text/plain")
      .send(`Installed for ${shop}. Token stored in memory. You can now hit your App Proxy: https://${stripPort(req.get("host"))}/apps/sitemaps/image.xml`);
  } catch (e) {
    console.error(e);
    return res.status(500).send("OAuth callback error");
  }
});

/* ========== App Proxy endpoints ========== */
/*
  Shopify proxies:
    /apps/sitemaps/image.xml       -> our server route /image.xml
    /apps/sitemaps/image-index.xml -> our server route /image-index.xml

  App Proxy automatically adds ?shop and ?signature
  Optional query:
    - type=products|collections|all (default: all)
    - page=1..N (simple pagination after combining URLs)
*/
app.get("/image.xml", async (req, res) => {
  try {
    // Verify proxy signature
    if (!verifyAppProxy(req)) return res.status(401).send("Invalid signature");

    const shop = String(req.query.shop || "");
    const accessToken = tokenStore.get(shop);
    if (!accessToken) {
      // Ask merchant to install
      const installUrl = `${HOST.replace(/\/$/, "")}/auth?shop=${encodeURIComponent(shop)}`;
      return res.status(403).type("text/plain").send(`App not installed for ${shop}. Visit ${installUrl}`);
    }

    const host = req.get("x-forwarded-host") || req.get("host");
    const type = (req.query.type || "all").toLowerCase(); // products|collections|all
    const page = Math.max(parseInt(req.query.page || "1", 10), 1);

    const nodes = [];

    if (type === "products" || type === "all") {
      const products = await getAllProductsWithImages(shop, accessToken);
      for (const p of products) {
        const pageUrl = pageUrlForProduct(host, p.handle, p.onlineStoreUrl);
        const images = (p.images?.edges || []).map((e) => e.node);
        if (!images.length) continue;
        const imageNodes = images.map((img) => buildImageNode(img.url, img.altText || p.title));
        nodes.push(buildUrlNode(pageUrl, imageNodes));
      }
    }

    if (type === "collections" || type === "all") {
      const collections = await getAllCollectionsWithImage(shop, accessToken);
      for (const c of collections) {
        if (!c.image?.url) continue;
        const pageUrl = pageUrlForCollection(host, c.handle);
        const imageNodes = [buildImageNode(c.image.url, c.image.altText || c.title)];
        nodes.push(buildUrlNode(pageUrl, imageNodes));
      }
    }

    // Pagination
    const start = (page - 1) * MAX_URLS_PER_FEED;
    const end = start + MAX_URLS_PER_FEED;
    const slice = nodes.slice(start, end);

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset
  xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
  xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
${slice.join("\n")}
</urlset>`;

    setXmlHeaders(res);
    return res.status(200).send(xml);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Sitemap generation error");
  }
});

// Simple echo endpoint for proxy reachability (no signature check so merchants can test easily)
app.get("/echo", (req, res) => res.type("text/plain").send("echo ok"));

/* ========== Optional: sitemap index for pagination ========== */
app.get("/image-index.xml", (req, res) => {
  const host = stripPort(req.get("x-forwarded-host") || req.get("host"));
  const urls = Array.from({ length: 5 }, (_, i) => i + 1).map(
    (n) => `<sitemap><loc>https://${host}/apps/sitemaps/image.xml?type=all&page=${n}</loc></sitemap>`
  );
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join("\n")}
</sitemapindex>`;
  setXmlHeaders(res);
  return res.status(200).send(xml);
});

/* ========== Health & Root ========== */
app.get("/health", (_req, res) => res.type("text/plain").send("ok"));
app.get("/", (_req, res) => {
  res
    .type("text/plain")
    .send("Image Sitemap Proxy is running. Use /health or call via Shopify App Proxy at /apps/sitemaps/image.xml");
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Image sitemap proxy (OAuth) on :${port}`));
