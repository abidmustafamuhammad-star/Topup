'use strict';
const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  user_id:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  code:       { type: String, required: true },
  attempts:   { type: Number, default: 0 },
  ip_address: { type: String, default: null },
  expires_at: { type: Date, required: true },
  used:       { type: Boolean, default: false },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

module.exports = mongoose.model('LoginVerification', schema);