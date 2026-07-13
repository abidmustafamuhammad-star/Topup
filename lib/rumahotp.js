'use strict';
const axios = require('axios');
const config = require('../config');

const http = axios.create({
  baseURL: config.rumahotp.baseUrl,
  timeout: 15_000,
  headers: {
    'x-apikey': config.rumahotp.apiKey,
    'Accept': 'application/json',
  },
});

function wrap(promise) {
  return promise.then(r => r.data).catch(err => {
    const msg = err.response?.data?.message || err.message || 'Server API error';
    const code = err.response?.data?.code || err.response?.status || 0;
    const e = new Error(msg); e.code = code; throw e;
  });
}

/** Saldo akun RumahOTP */
const getBalance = () => wrap(http.get('/api/v1/user/balance'));

/** Daftar semua layanan */
const getServices = () => wrap(http.get('/api/v2/services'));

/** Daftar negara untuk layanan tertentu */
const getCountries = (service_id) => wrap(http.get('/api/v2/countries', { params: { service_id } }));

/** Daftar operator per negara & provider */
const getOperators = (country, provider_id) => wrap(http.get('/api/v2/operators', { params: { country, provider_id } }));

/** Buat order nomor virtual */
const createOrder = ({ number_id, provider_id, operator_id }) =>
  wrap(http.get('/api/v2/orders', { params: { number_id, provider_id, operator_id } }));

/** Cek status / ambil kode OTP */
const getOrderStatus = (order_id) => wrap(http.get('/api/v1/orders/get_status', { params: { order_id } }));

/** Ubah status order: cancel | done | resend */
const setOrderStatus = (order_id, status) => wrap(http.get('/api/v1/orders/set_status', { params: { order_id, status } }));

module.exports = {
  getBalance,
  getServices,
  getCountries,
  getOperators,
  createOrder,
  getOrderStatus,
  setOrderStatus,
};
