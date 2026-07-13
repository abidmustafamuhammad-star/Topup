'use strict';
const mongoose = require('mongoose');
const config   = require('../config');

let connected = false;

async function connect() {
  if (connected) return;
  await mongoose.connect(config.database.uri);
  connected = true;

  // Seed default settings jika belum ada
  const Setting = require('./models/Setting');
  const defaults = [
    { key: 'markup_percent',  value: '15' },
    { key: 'site_name',       value: 'ReceOTP' },
    { key: 'site_tagline',    value: 'Nomor Virtual OTP Instan, Aman, Murah' },
    { key: 'maintenance_mode',value: '0' },
    { key: 'auto_cancel_min', value: '20' },
  ];
  for (const s of defaults) {
    await Setting.findOneAndUpdate({ key: s.key }, s, { upsert: true, new: true });
  }
}

// Panggil connect() di awal setiap request via middleware
async function ensureConnected() {
  if (!connected) await connect();
}

module.exports = { connect, ensureConnected };