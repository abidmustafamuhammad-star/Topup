'use strict';
const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  user_id:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  action:     { type: String, required: true },
  details:    { type: mongoose.Schema.Types.Mixed, default: {} },
  ip_address: { type: String, default: null },
  status:     { type: String, enum: ['success','failed'], default: 'success' },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

module.exports = mongoose.model('AuditLog', schema);