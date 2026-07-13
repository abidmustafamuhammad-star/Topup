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

module.exports = { log, getIp, sanitize, genToken, genCode, formatRp, applyMarkup, genPakasirOrderId, auditLog, balanceLog, getSetting, setSetting };
