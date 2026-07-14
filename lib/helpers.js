'use strict';
const crypto = require('crypto');
const config = require('../config');

const log = {
  info:  (...a) => console.log('[INFO]',  new Date().toISOString(), ...a),
  warn:  (...a) => console.warn('[WARN]',  new Date().toISOString(), ...a),
  error: (...a) => console.error('[ERROR]', new Date().toISOString(), ...a),
};

const getIp = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || '0.0.0.0';

const sanitize = (str = '') => String(str).replace(/[<>"']/g, '').trim().slice(0, 500);

const genToken = (bytes = 32) => crypto.randomBytes(bytes).toString('hex');

const genCode = (digits = 6) => String(crypto.randomInt(0, 10 ** digits)).padStart(digits, '0');

const formatRp = (n) => 'Rp ' + Number(n || 0).toLocaleString('id-ID');

const applyMarkup = (basePrice, markupPct) => Math.ceil(basePrice * (1 + markupPct / 100));

const genPakasirOrderId = (prefix = 'OTP') => `${prefix}${Date.now()}${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

/** Audit log ke DB (fire-and-forget) */
async function auditLog(_, userId, action, details, ip, status = 'success') {
  try {
    const AuditLog = require('./models/AuditLog');
    await AuditLog.create({ user_id: userId || null, action, details: details || {}, ip_address: ip, status });
  } catch (e) { log.error('auditLog', e.message); }
}

/** Balance log ke DB */
async function balanceLog(_, userId, type, amount, balanceBefore, balanceAfter, refType, refId, note) {
  const BalanceLog = require('./models/BalanceLog');
  await BalanceLog.create({
    user_id: userId, type, amount, balance_before: balanceBefore,
    balance_after: balanceAfter, reference_type: refType,
    reference_id: refId || null, note: note || null,
  });
}

/** Ambil setting dari DB dengan fallback */
async function getSetting(_, key, fallback = null) {
  const Setting = require('./models/Setting');
  const row = await Setting.findOne({ key });
  return row ? row.value : fallback;
}

/** Update setting di DB */
async function setSetting(_, key, value) {
  const Setting = require('./models/Setting');
  await Setting.findOneAndUpdate({ key }, { key, value }, { upsert: true });
}
// ============================================================
// RATE LIMIT & LOGIN LOCKOUT (disimpan di Mongo, aman untuk Vercel/serverless)
// Didefinisikan langsung di sini biar tidak perlu bikin file baru.
// ============================================================
const mongoose = require('mongoose');

const rateLimitSchema = new mongoose.Schema({
  key:      { type: String, required: true, unique: true },
  count:    { type: Number, default: 0 },
  reset_at: { type: Date, required: true },
});
rateLimitSchema.index({ reset_at: 1 }, { expireAfterSeconds: 0 });
const RateLimit = mongoose.models.RateLimit || mongoose.model('RateLimit', rateLimitSchema);

const loginAttemptSchema = new mongoose.Schema({
  ip_address: { type: String, required: true, unique: true },
  count:      { type: Number, default: 0 },
  lock_until: { type: Date, default: null },
  expires_at: { type: Date, required: true },
});
loginAttemptSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });
const LoginAttempt = mongoose.models.LoginAttempt || mongoose.model('LoginAttempt', loginAttemptSchema);

async function checkRateLimit(key, windowMs, max) {
  const now = new Date();
  const doc = await RateLimit.findOne({ key }).lean();
  if (!doc || doc.reset_at <= now) {
    await RateLimit.findOneAndUpdate(
      { key },
      { key, count: 1, reset_at: new Date(now.getTime() + windowMs) },
      { upsert: true }
    );
    return true;
  }
  if (doc.count >= max) return false;
  await RateLimit.updateOne({ key }, { $inc: { count: 1 } });
  return true;
}

async function getLoginLock(ip) {
  return LoginAttempt.findOne({ ip_address: ip }).lean();
}

async function registerFailedLogin(ip, maxAttempts, lockoutMs) {
  const now = new Date();
  const existing = await LoginAttempt.findOne({ ip_address: ip }).lean();
  const count = (existing?.count || 0) + 1;
  const lockUntil = count >= maxAttempts ? new Date(now.getTime() + lockoutMs) : (existing?.lock_until || null);
  await LoginAttempt.findOneAndUpdate(
    { ip_address: ip },
    { ip_address: ip, count, lock_until: lockUntil, expires_at: new Date(now.getTime() + lockoutMs + 60_000) },
    { upsert: true }
  );
}

async function clearLoginAttempts(ip) {
  await LoginAttempt.deleteOne({ ip_address: ip });
}

/** Refund saldo user untuk order yang dibatalkan/gagal */
async function refundOrderBalance(userId, amount, orderId, note) {
  const User = require('./models/User');
  const u = await User.findById(userId);
  if (!u) return;
  const bal = u.balance;
  await User.updateOne({ _id: userId }, { $inc: { balance: amount } });
  await balanceLog(null, userId, 'credit', amount, bal, Number(bal) + Number(amount), 'refund', orderId, note);
  if (u.telegram_chat_id) {
    const tg = require('./telegram');
    await tg.sendMessage(u.telegram_chat_id, `♻️ Saldo dikembalikan Rp ${Number(amount).toLocaleString('id-ID')} — ${note}`);
  }
}

/** Ambil harga & stok ASLI dari provider — jangan pernah percaya base_price dari client */
async function resolveCanonicalPrice(service_id, number_id, provider_id) {
  const rumahotp = require('./rumahotp');
  const result = await rumahotp.getCountries(service_id);
  const raw = result?.data || [];
  const country = raw.find(c => String(c.number_id) === String(number_id));
  if (!country) return null;
  const entry = (country.pricelist || []).find(p => String(p.provider_id) === String(provider_id));
  if (!entry) return null;
  return { base_price: Number(entry.price || 0), stock: entry.available ?? entry.stock };
}
module.exports = {
  log, getIp, sanitize, genToken, genCode, formatRp, applyMarkup, genPakasirOrderId,
  auditLog, balanceLog, getSetting, setSetting,
  checkRateLimit, getLoginLock, registerFailedLogin, clearLoginAttempts,
  refundOrderBalance, resolveCanonicalPrice,
};
