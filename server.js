import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import { URL } from "url";

const app = express();

/* ========= CONFIG via ENV (HYBRID) =========
Required:
  SHOP                -> e.g. smelltoimpress.myshopify.com
  ADMIN_API_TOKEN     -> Admin API token (read_products, read_translations)
  SHARED_SECRET       -> App Proxy "API secret key" from the Partner App (with App Proxy)

Optional:
  API_VERSION         -> default 2024-04
  CACHE_TTL_SECONDS   -> default 900
  MAX_URLS_PER_FEED   -> default 5000
  DEFAULT_PER_PAGE    -> default 200
  HTTP_TIMEOUT_MS     -> default 12000
  TRANS_CONCURRENCY   -> default 8
  DISABLE_HMAC        -> "1" to bypass proxy HMAC check (local testing only)
============================================= */

const SHOP = process.env.SHOP || "";
const ADMIN_API_TOKEN = process.env.ADMIN_API_TOKEN || "";
const SHARED_SECRET = process.env.SHARED_SECRET || "";
const DISABLE_HMAC = String(process.env.DISABLE_HMAC || "0") === "1";

const API_VERSION = process.env.API_VERSION || "2024-04";
const CACHE_TTL_SECONDS = Number(process.env.CACHE_TTL_SECONDS || 900);
const MAX_URLS_PER_FEED = Number(process.env.MAX_URLS_PER_FEED || 5000);
const DEFAULT_PER_PAGE = Math.min(Number(process.env.DEFAULT_PER_PAGE || 200), MAX_URLS_PER_FEED);
const HTTP_TIMEOUT_MS = Number(process.env.HTTP_TIMEOUT_MS || 12000);
const TRANS_CONCURRENCY = Math.max(1, Number(process.env.TRANS_CONCURRENCY || 8));

if (!SHOP) console.error("[startup] Missing SHOP env");
if (!ADMIN_API_TOKEN) console.error("[startup] Missing ADMIN_API_TOKEN env");
if (!SHARED_SECRET) console.error("[startup] Missing SHARED_SECRET env");

const responseCache = new Map(); // key -> { body, expiresAt }

/* ---------- Utils ---------- */

function cacheKey(parts){return Object.entries(parts).map(([k,v])=>`${k}=${v}`).sort().join("|");}
function setXmlHeaders(res){res.set("Content-Type","application/xml; charset=utf-8");res.set("Cache-Control",`public, max-age=${CACHE_TTL_SECONDS}`);}
function x(s=""){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function stripPort(host){return (host||"").replace(/:.+$/,"");}
function preferHostImageUrl(originalUrl, host){
  try{
    const u=new URL(originalUrl);
    if(u.hostname!=="cdn.shopify.com") return originalUrl;
    const p=u.pathname;
    const iP=p.indexOf("/products/"); const iF=p.indexOf("/files/");
    let rebuilt=null;
    if(iP!==-1) rebuilt=`/cdn/shop${p.substring(iP)}${u.search||""}`;
    else if(iF!==-1) rebuilt=`/cdn/shop${p.substring(iF)}${u.search||""}`;
    return rebuilt?`https://${host}${rebuilt}`:originalUrl;
  }catch{return originalUrl;}
}
function pageUrlForProduct(host, handle, onlineStoreUrl){
  const h=stripPort(host);
  if(onlineStoreUrl) return onlineStoreUrl.replace(/^https?:\/\/[^/]+/,`https://${h}`);
  return `https://${h}/products/${handle}`;
}
function pageUrlForCollection(host, handle){
  const h=stripPort(host);
  return `https://${h}/collections/${handle}`;
}

/** Hardened App Proxy HMAC check */
function verifyProxyHmac(req){
  if (DISABLE_HMAC) return true;
  const query = { ...req.query };
  const provided = (query.signature || query.sig || "").toString().toLowerCase();
  delete query.signature; delete query.sig;
  if (!SHARED_SECRET || !provided) return false;
  const payload = Object.keys(query).sort().map(k => `${k}=${query[k]}`).join("");
  const expected = crypto.createHmac("sha256", SHARED_SECRET).update(payload).digest("hex").toLowerCase();
  try {
    const a = Buffer.from(expected, "hex");
    const b = Buffer.from(provided, "hex");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

function getLocaleForHost(host, override){
  if(override) return override.toLowerCase();
  const h=(host||"").toLowerCase();
  if(h.endsWith(".fr")) return "fr";
  if(h.endsWith(".it")) return "it";
  if(h.startsWith("ko.")) return "ko";
  if(h.startsWith("ar.")) return "ar";
  if(h.startsWith("iw.")) return "he";
  if(h.endsWith(".nl")) return "nl";
  if(h.endsWith(".ch")) return "de";
  return "en";
}
function numericIdFromGid(gid){ if(!gid) return null; const parts=String(gid).split("/"); return parts.length?parts[parts.length-1]:null; }
async function timedFetch(url, opts={}, timeoutMs=HTTP_TIMEOUT_MS){
  const c=new AbortController(); const t=setTimeout(()=>c.abort(),timeoutMs);
  try{return await fetch(url,{...opts,signal:c.signal});} finally{clearTimeout(t);}
}
async function pMap(items, limit, mapper){
  const ret=[]; const executing=[];
  for(const item of items){
    const p=Promise.resolve().then(()=>mapper(item));
    ret.push(p);
    const e=p.then(()=>executing.splice(executing.indexOf(e),1));
    executing.push(e);
    if(executing.length>=limit) await Promise.race(executing);
  }
  return Promise.all(ret);
}

/* ---------- Admin API fetchers with robust pagination ---------- */

/**
 * Robust cursor pagination:
 * 1) SKIP PHASE: advance by pages of `first` until we pass `offset` (no collecting)
 * 2) COLLECT PHASE: collect up to `take` items into `out`
 * This avoids edge-cases where interleaving skip/collect lost elements.
 */
async function gqlPagedSlice({ query, selectEdges, selectPageInfo, first, offset, take, debug }) {
  let after = null;
  let skipped = 0;
  const out = [];

  // --- Skip phase ---
  while (skipped < offset) {
    const want = Math.min(first, offset - skipped);
    const resp = await timedFetch(`https://${SHOP}/admin/api/${API_VERSION}/graphql.json`,{
      method:"POST",
      headers:{ "X-Shopify-Access-Token":ADMIN_API_TOKEN,"Content-Type":"application/json"},
      body:JSON.stringify({ query, variables:{ first: want, after }})
    });
    if(!resp.ok){ const text=await resp.text(); throw new Error(`Admin API ${resp.status}: ${text}`); }
    const json=await resp.json();
    const edges = selectEdges(json) || [];
    if (!edges.length) break; // nothing more
    skipped += edges.length;
    after = edges[edges.length-1].cursor;
    const pageInfo = selectPageInfo(json);
    if (!pageInfo?.hasNextPage) break;
  }

  // --- Collect phase ---
  while (out.length < take) {
    const need = take - out.length;
    const want = Math.min(first, need);
    const resp = await timedFetch(`https://${SHOP}/admin/api/${API_VERSION}/graphql.json`,{
      method:"POST",
      headers:{ "X-Shopify-Access-Token":ADMIN_API_TOKEN,"Content-Type":"application/json"},
      body:JSON.stringify({ query, variables:{ first: want, after }})
    });
    if(!resp.ok){ const text=await resp.text(); throw new Error(`Admin API ${resp.status}: ${text}`); }
    const json=await resp.json();
    const edges = selectEdges(json) || [];
    if (!edges.length) break;
    for (const e of edges) {
      out.push(e.node);
      if (out.length >= take) break;
    }
    after = edges[edges.length-1].cursor;
    const pageInfo = selectPageInfo(json);
    if (!pageInfo?.hasNextPage) break;
  }

  if (debug) {
    out._debug = { skipped, collected: out.length };
  }
  return out;
}

async function getProductsSlice(offset, limit, debug=false){
  const query=`
    query Products($first:Int!, $after:String) {
      products(first:$first, after:$after, query:"status:active", sortKey:UPDATED_AT, reverse:true) {
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
    }`;
  return gqlPagedSlice({
    query,
    selectEdges: j => j?.data?.products?.edges,
    selectPageInfo: j => j?.data?.products?.pageInfo,
    first: 100,           // batch size to talk to Shopify
    offset,               // skip this many nodes first
    take: limit,          // then collect exactly this many
    debug
  });
}

async function getCollectionsSlice(offset, limit, debug=false){
  const query=`
    query Collections($first:Int!, $after:String) {
      collections(first:$first, after:$after, query:"published_status:published", sortKey:UPDATED_AT, reverse:true) {
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
    }`;
  return gqlPagedSlice({
    query,
    selectEdges: j => j?.data?.collections?.edges,
    selectPageInfo: j => j?.data?.collections?.pageInfo,
    first: 200,
    offset,
    take: limit,
    debug
  });
}

/* ---------- Translations (Admin REST) ---------- */

async function fetchProductTranslations(numericId, locale){
  const url=`https://${SHOP}/admin/api/${API_VERSION}/translations.json?locale=${encodeURIComponent(locale)}&resource_type=Product&resource_id=${numericId}`;
  const resp=await timedFetch(url,{ headers:{ "X-Shopify-Access-Token":ADMIN_API_TOKEN,"Content-Type":"application/json"}});
  if(!resp.ok) return null;
  const json=await resp.json(); return json?.translations||null;
}
async function fetchCollectionTranslations(numericId, locale){
  const url=`https://${SHOP}/admin/api/${API_VERSION}/translations.json?locale=${encodeURIComponent(locale)}&resource_type=Collection&resource_id=${numericId}`;
  const resp=await timedFetch(url,{ headers:{ "X-Shopify-Access-Token":ADMIN_API_TOKEN,"Content-Type":"application/json"}});
  if(!resp.ok) return null;
  const json=await resp.json(); return json?.translations||null;
}
function extractTranslatedValue(translations, keyExact){
  if(!translations) return "";
  for(const t of translations){ if(t.key===keyExact && t.value) return String(t.value); }
  return "";
}
function buildImageAltMapFromTranslations(translations){
  const map=new Map();
  if(!translations) return map;
  for(const t of translations){
    if(!t?.key||!t?.value) continue;
    if(t.key==="image.alt_text"){ map.set("*",String(t.value)); continue; }
    const m=t.key.match(/^image\[(\d+)\]\.alt$/i);
    if(m) map.set(m[1],String(t.value));
  }
  return map;
}

/* ---------- XML builders ---------- */

function buildImageNode(loc, title, caption){
  return `
        <image:image>
          <image:loc>${x(loc)}</image:loc>
          <image:title>${x(title || "")}</image:title>
          <image:caption>${x(caption || "")}</image:caption>
        </image:image>`;
}
function buildUrlNode(pageLoc, lastmodISO, imageNodes){
  return `<url>
      <loc>${x(pageLoc)}</loc>
      ${lastmodISO?`<lastmod>${x(lastmodISO)}</lastmod>`:""}${imageNodes.join("")}
    </url>`;
}

/* ---------- Main App Proxy endpoints ---------- */

app.get("/image.xml", async (req,res)=>{
  try{
    if(!verifyProxyHmac(req)) return res.status(401).send("Invalid signature");

    const forwardedHost=req.get("x-forwarded-host")||req.get("host");
    const host=stripPort(forwardedHost);

    const page=Math.max(parseInt(req.query.page||"1",10),1);
    const perPageRaw=Math.max(parseInt(req.query.per_page||String(DEFAULT_PER_PAGE),10),1);
    const perPage=Math.min(perPageRaw,MAX_URLS_PER_FEED);
    const type=(req.query.type||"all").toLowerCase(); // products|collections|all
    const preferHost=String(req.query.prefer_host||"1")==="1";
    const locale=getLocaleForHost(host, req.query.locale);
    const debug=String(req.query.debug||"0")==="1";

    const key=cacheKey({route:"image.xml",host,page,perPage,type,preferHost,locale});
    const hit=responseCache.get(key);
    const now=Date.now();
    if(hit && hit.expiresAt>now){ setXmlHeaders(res); return res.status(200).send(hit.body); }

    const offset=(page-1)*perPage;
    const nodes=[];

    // ----- PRODUCTS -----
    let diag = { locale, host, page, perPage, type };
    if(type==="products"||type==="all"){
      const products=await getProductsSlice(offset, perPage, debug);

      // fetch translations in parallel
      const prodTrans=await pMap(
        products.map(p=>({ p, idNum:numericIdFromGid(p.id) })), TRANS_CONCURRENCY,
        async ({p,idNum})=>{
          let trs=null;
          if(idNum) trs=await fetchProductTranslations(idNum, locale);
          return { id:p.id, trs };
        }
      );
      const transMap=new Map(prodTrans.map(r=>[r.id, r.trs||[]]));

      for(const p of products){
        const pageUrl=pageUrlForProduct(host, p.handle, p.onlineStoreUrl);
        const images=(p.images?.edges||[]).map(e=>e.node);
        if(!images.length) continue;

        const trs=transMap.get(p.id)||[];
        const productTitleTr=extractTranslatedValue(trs,"title");
        const imageAltMap=buildImageAltMapFromTranslations(trs);
        const productTitleFallback = productTitleTr || p.title || "";

        const imageNodes = images.map(img=>{
          const imgIdNum=numericIdFromGid(img.id);
          const translatedAlt = (imgIdNum && imageAltMap.get(imgIdNum)) || imageAltMap.get("*") || "";
          const resolved = translatedAlt || productTitleFallback; // caption+title from FR alt or FR title
          const imgUrl = preferHost ? preferHostImageUrl(img.url, host) : img.url;
          return buildImageNode(imgUrl, resolved, resolved);
        });

        nodes.push(buildUrlNode(pageUrl, p.updatedAt, imageNodes));
      }

      if (debug && products._debug) diag.products_debug = products._debug;
    }

    // ----- COLLECTIONS -----
    if(type==="collections"||type==="all"){
      const collections=await getCollectionsSlice(offset, perPage, debug);

      const colTrans=await pMap(
        collections.map(c=>({ c, idNum:numericIdFromGid(c.id) })), TRANS_CONCURRENCY,
        async ({c,idNum})=>{
          let trs=null;
          if(idNum) trs=await fetchCollectionTranslations(idNum, locale);
          return { id:c.id, trs };
        }
      );
      const transMap=new Map(colTrans.map(r=>[r.id, r.trs||[]]));

      for(const c of collections){
        if(!c.image?.url) continue;
        const pageUrl=pageUrlForCollection(host, c.handle);

        const trs=transMap.get(c.id)||[];
        const collectionTitleTr=extractTranslatedValue(trs,"title");
        const imgIdNum=numericIdFromGid(c.image?.id);

        let imageAltTr="";
        for(const t of trs){
          if(!t?.key||!t?.value) continue;
          if(t.key==="image.alt_text") imageAltTr=String(t.value);
          const m=t.key.match(/^image\[(\d+)\]\.alt$/i);
          if(m && imgIdNum && m[1]===String(imgIdNum)) imageAltTr=String(t.value);
        }

        const resolved = imageAltTr || collectionTitleTr || c.title || "";
        const imgUrl = preferHost ? preferHostImageUrl(c.image.url, host) : c.image.url;
        const imageNodes=[buildImageNode(imgUrl, resolved, resolved)];

        nodes.push(buildUrlNode(pageUrl, c.updatedAt, imageNodes));
      }

      if (debug && collections._debug) diag.collections_debug = collections._debug;
    }

    const debugComment = debug
      ? `\n<!-- ${Object.entries(diag).map(([k,v])=>`${k}=${v}`).join(" ")} -->\n`
      : "";

    const xml=`<?xml version="1.0" encoding="UTF-8"?>${debugComment}
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
${nodes.join("\n")}
</urlset>`;

    responseCache.set(key,{ body:xml, expiresAt: now + CACHE_TTL_SECONDS*1000 });
    setXmlHeaders(res);
    return res.status(200).send(xml);

  }catch(e){
    console.error(e);
    return res.status(500).send("Sitemap generation error");
  }
});

/** Proxy signature debugger */
app.get("/proxy-debug", (req, res) => {
  const q = { ...req.query };
  const given = (q.signature || q.sig || "").toString().toLowerCase();
  delete q.signature; delete q.sig;
  const payload = Object.keys(q).sort().map(k => `${k}=${q[k]}`).join("");
  const expected = SHARED_SECRET
    ? crypto.createHmac("sha256", SHARED_SECRET).update(payload).digest("hex").toLowerCase()
    : "(SHARED_SECRET MISSING)";
  res.type("text/plain").send(
    [
      `host=${req.get("host")}`,
      `path=${req.path}`,
      `payload=${payload}`,
      `expected=${expected}`,
      `given=${given}`,
      `match=${expected === given}`,
    ].join("\n")
  );
});

/* ---------- Sitemap index (with proper escaping) ---------- */
app.get("/image-index.xml",(req,res)=>{
  const forwardedHost=req.get("x-forwarded-host")||req.get("host");
  const host=stripPort(forwardedHost);
  const pages=Math.max(Number(req.query.pages||5),1);
  const type=String(req.query.type||"products");
  const perPage=Math.max(Number(req.query.per_page||DEFAULT_PER_PAGE),1);
  const locale= req.query.locale ? `&locale=${encodeURIComponent(req.query.locale)}` : "";

  const urls=[];
  for(let n=1;n<=pages;n++){
    const loc=`https://${host}/apps/sitemaps/image.xml?type=${encodeURIComponent(type)}&page=${n}&per_page=${perPage}${locale}`;
    urls.push(`<sitemap><loc>${x(loc)}</loc></sitemap>`);
  }

  const xml=`<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join("\n")}
</sitemapindex>`;
  setXmlHeaders(res);
  return res.status(200).send(xml);
});

// Health & root
app.get("/health",(_req,res)=>res.type("text/plain").send("ok"));
app.get("/",(_req,res)=>res.type("text/plain").send("Image Sitemap Proxy (hybrid) running. Use /apps/sitemaps/image.xml"));

const port=process.env.PORT||3000;
app.listen(port,()=>console.log(`Image sitemap proxy (hybrid) on :${port}`));
