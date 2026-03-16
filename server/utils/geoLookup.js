// server/utils/geoLookup.js
// Simple wrapper around geoip-lite to provide normalized results.
// Falls back to null if lookup fails.
//
// Note: install dependency: npm install geoip-lite
const geoip = require('geoip-lite');

function safeNumber(v) {
  if (typeof v === 'number' && !Number.isNaN(v)) return v;
  return null;
}

function geoLookup(ip) {
  if (!ip) return null;
  try {
    const geo = geoip.lookup(ip);
    if (!geo) return null;
    return {
      country: geo.country || null,
      region: geo.region || null,
      city: geo.city || null,
      latitude: (Array.isArray(geo.ll) && geo.ll.length > 0) ? safeNumber(geo.ll[0]) : null,
      longitude: (Array.isArray(geo.ll) && geo.ll.length > 1) ? safeNumber(geo.ll[1]) : null,
      provider: 'geoip-lite'
    };
  } catch (err) {
    console.warn('geoLookup error:', err && err.message ? err.message : err);
    return null;
  }
}

module.exports = { geoLookup };
