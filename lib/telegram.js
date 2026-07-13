'use strict';
const axios = require('axios');
const config = require('../config');

const base = () => `https://api.telegram.org/bot${config.telegram.botToken}`;

async function sendMessage(chat_id, text, parse_mode = 'HTML') {
  if (!config.telegram.botToken) return null;
  try {
    const r = await axios.post(`${base()}/sendMessage`, { chat_id, text, parse_mode });
    return r.data;
  } catch (e) {
    console.error('[Telegram] sendMessage error:', e.response?.data || e.message);
    return null;
  }
}

async function getMe() {
  const r = await axios.get(`${base()}/getMe`);
  return r.data;
}

async function setWebhook(url) {
  const r = await axios.post(`${base()}/setWebhook`, { url });
  return r.data;
}

/** Kirim kode OTP login ke user via Telegram */
async function sendLoginCode(chat_id, code, siteName) {
  const text = [
    `🔐 <b>Kode Verifikasi Login ${siteName}</b>`,
    '',
    `Kode kamu: <code>${code}</code>`,
    '',
    '⏰ Berlaku selama <b>5 menit</b>.',
    '⚠️ Jangan bagikan kode ini ke siapapun.',
    '',
    '<i>Jika kamu tidak sedang login, abaikan pesan ini.</i>',
  ].join('\n');
  return sendMessage(chat_id, text);
}

/** Kirim notifikasi OTP masuk */
async function sendOtpNotification(chat_id, service, phone, otpCode, siteName) {
  const text = [
    `✅ <b>OTP Diterima — ${siteName}</b>`,
    '',
    `📱 Nomor: <code>${phone}</code>`,
    `🛎️ Layanan: <b>${service}</b>`,
    `🔑 Kode OTP: <code>${otpCode}</code>`,
    '',
    'Segera gunakan kode ini sebelum kedaluwarsa.',
  ].join('\n');
  return sendMessage(chat_id, text);
}

/** Kirim notifikasi transaksi berhasil */
async function sendPaymentNotification(chat_id, amount, siteName) {
  const text = [
    `💰 <b>Pembayaran Diterima — ${siteName}</b>`,
    '',
    `Jumlah: <b>Rp ${Number(amount).toLocaleString('id-ID')}</b>`,
    'Nomor virtual sedang disiapkan...',
  ].join('\n');
  return sendMessage(chat_id, text);
}

module.exports = { sendMessage, getMe, setWebhook, sendLoginCode, sendOtpNotification, sendPaymentNotification };
