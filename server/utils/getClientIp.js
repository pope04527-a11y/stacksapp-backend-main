// server/utils/getClientIp.js
// Robust extraction of client IP from an Express request object.
// Handles X-Forwarded-For, CF-Connecting-IP, Fastly, X-Real-IP, req.ip and socket fallbacks.

module.exports = function getClientIp(req) {
  if (!req || !req.headers) return null;

  // X-Forwarded-For may contain a comma-separated list: first item is the original client IP
  const xForwardedFor = req.headers['x-forwarded-for'] || req.headers['X-Forwarded-For'];
  if (typeof xForwardedFor === 'string' && xForwardedFor.length) {
    const parts = xForwardedFor.split(',').map(s => s.trim()).filter(Boolean);
    if (parts.length) return parts[0];
  }

  // Cloudflare, Fastly and other providers
  if (req.headers['cf-connecting-ip']) return req.headers['cf-connecting-ip'];
  if (req.headers['fastly-client-ip']) return req.headers['fastly-client-ip'];
  if (req.headers['x-real-ip']) return req.headers['x-real-ip'];

  // Express sets req.ip when trust proxy is enabled
  if (req.ip) return req.ip;

  // Fallback to connection remote address
  const remoteAddress = (req.connection && (req.connection.remoteAddress || req.connection.socket && req.connection.socket.remoteAddress))
    || (req.socket && (req.socket.remoteAddress || (req.socket.socket && req.socket.socket.remoteAddress)))
    || null;

  if (typeof remoteAddress === 'string') {
    // strip IPv6 prefix if present (e.g., ::ffff:127.0.0.1)
    return remoteAddress.replace(/^::ffff:/, '');
  }

  return null;
};
