'use strict';
const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  user_id:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  token:      { type: String, required: true, unique: true },
  expires_at: { type: Date, required: true },
  used:       { type: Boolean, default: false },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

module.exports = mongoose.model('TelegramLinkToken', schema);