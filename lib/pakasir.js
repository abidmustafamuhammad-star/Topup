'use strict';
const axios = require('axios');
const config = require('../config');

const http = axios.create({ baseURL: config.pakasir.baseUrl, timeout: 15_000 });

function wrap(promise) {
  return promise.then(r => r.data).catch(err => {
    const msg = err.response?.data?.message || err.message || 'payment error';
    const e = new Error(msg); e.code = err.response?.status || 0; throw e;
  });
}

function creds() {
  return { project: config.pakasir.project, api_key: config.pakasir.apiKey };
}

/** Buat transaksi QRIS */
const createQris = (order_id, amount) =>
  wrap(http.post('/api/transactioncreate/qris', { ...creds(), order_id, amount }));

/** Detail / status transaksi (untuk validasi webhook) */
const getDetail = (order_id, amount) =>
  wrap(http.get('/api/transactiondetail', { params: { ...creds(), order_id, amount } }));

/** Cancel transaksi */
const cancelTransaction = (order_id, amount) =>
  wrap(http.post('/api/transactioncancel', { ...creds(), order_id, amount }));

module.exports = { createQris, getDetail, cancelTransaction };
