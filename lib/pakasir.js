'use strict';
const axios = require('axios');
const config = require('../config');

const http = axios.create({ baseURL: config.pakasir.baseUrl, timeout: 15_000 });

function wrap(promise) {
  return promise.then(r => r.data).catch(err => {
    const status = err.response?.status || 0;
    const body   = err.response?.data;
    console.error('[Pakasir] request gagal:', status, body ? JSON.stringify(body) : err.message);
    const msg = body?.message || err.message || 'payment error';
    const e = new Error(msg); e.code = status; throw e;
  });
}

function creds() {
  return { project: config.pakasir.project, api_key: config.pakasir.apiKey };
}

/**
 * Buat transaksi QRIS.
 * PENTING: respons asli Pakasir nested di bawah "payment", dan field kode QR
 * namanya "payment_number" (BUKAN "qr_string"). Di-unwrap di sini supaya
 * pemanggil (api/index.js) tetap bisa pakai qrData.qr_string seperti biasa.
 */
const createQris = async (order_id, amount) => {
  const r = await wrap(http.post('/api/transactioncreate/qris', { ...creds(), order_id, amount }));
  const p = r?.payment || {};
  return {
    qr_string:     p.payment_number || null,
    amount:        p.amount,
    fee:           p.fee,
    total_payment: p.total_payment,
    expired_at:    p.expired_at || null,
  };
};

/**
 * Detail / status transaksi (untuk validasi webhook).
 * PENTING: respons asli Pakasir nested di bawah "transaction" — di-unwrap di sini.
 */
const getDetail = async (order_id, amount) => {
  const r = await wrap(http.get('/api/transactiondetail', { params: { ...creds(), order_id, amount } }));
  return r?.transaction || {};
};

/** Cancel transaksi */
const cancelTransaction = (order_id, amount) =>
  wrap(http.post('/api/transactioncancel', { ...creds(), order_id, amount }));

module.exports = { createQris, getDetail, cancelTransaction };
