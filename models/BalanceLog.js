'use strict';
const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  user_id:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type:           { type: String, enum: ['credit','debit'], required: true },
  amount:         { type: Number, required: true },
  balance_before: { type: Number, required: true },
  balance_after:  { type: Number, required: true },
  reference_type: { type: String, enum: ['deposit','order','refund','admin_adjust'], required: true },
  reference_id:   { type: mongoose.Schema.Types.ObjectId, default: null },
  note:           { type: String, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

module.exports = mongoose.model('BalanceLog', schema);