// server/utils/geoLookup.js
// Robust geo lookup: try geoip-lite first (offline). If not available, attempt public API fallback (ipapi.co).
// This file is defensive so missing optional dependencies won't crash the server.

let geoip = null;
try {
  geoip = require('geoip-lite');
} catch (err) {
  // geoip-lite not installed or failed to load — we will fallback to a public API (if axios available)
  geoip = null;
  console.warn('geoip-lite not available; falling back to HTTP lookup when possible.');
}

let axios = null;
try {
  axios = require('axios');
} catch (err) {
  axios = null;
}

function safeNumber(v) {
  if (typeof v === 'number' && !Number.isNaN(v)) return v;
  return null;
}

async function httpGeoLookup(ip) {
  if (!ip || !axios) return null;
  try {
    // ipapi.co provides a simple JSON endpoint without requiring an API key for basic usage.
    const url = `https://ipapi.co/${ip}/json/`;
    const res = await axios.get(url, { timeout: 2500 });
    const data = res && res.data ? res.data : null;
    if (!data) return null;
    return {
      country: data.country_name || data.country || null,
      region: data.region || null,
      city: data.city || null,
      latitude: data.latitude || data.lat || null,
      longitude: data.longitude || data.lon || null,
      provider: 'ipapi.co'
    };
  } catch (err) {
    // network failed or blocked; just return null
    // console.warn('httpGeoLookup failed', err && err.message ? err.message : err);
    return null;
  }
}

/**
 * geoLookup
 * - Try an offline lookup using geoip-lite if available.
 * - If not available or lookup fails, fall back to a lightweight HTTP lookup (ipapi.co) if axios is present.
 * - Returns normalized object { country, region, city, latitude, longitude, provider } or null.
 */
async function geoLookup(ip) {
  if (!ip) return null;
  try {
    if (geoip) {
      const geo = geoip.lookup(ip);
      if (geo) {
        return {
          country: geo.country || null,
          region: geo.region || null,
          city: geo.city || null,
          latitude: (Array.isArray(geo.ll) && geo.ll.length > 0) ? safeNumber(geo.ll[0]) : null,
          longitude: (Array.isArray(geo.ll) && geo.ll.length > 1) ? safeNumber(geo.ll[1]) : null,
          provider: 'geoip-lite'
        };
      }
    }

    // offline lookup failed or not available -> try HTTP provider
    const httpGeo = await httpGeoLookup(ip);
    if (httpGeo) return httpGeo;

    return null;
  } catch (err) {
    console.warn('geoLookup unexpected error:', err && err.message ? err.message : err);
    return null;
  }
}

module.exports = { geoLookup };
