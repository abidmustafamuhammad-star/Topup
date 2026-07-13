'use strict';
const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  order_id:            { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true },
  user_id:             { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  pakasir_order_id:    { type: String, required: true, unique: true },
  amount:              { type: Number, required: true },
  status:              { type: String, enum: ['pending','success','failed','cancelled'], default: 'pending' },
  payment_method:      { type: String, default: null },
  qr_string:           { type: String, default: null },
  expired_at:          { type: Date, default: null },
  raw_webhook_payload: { type: mongoose.Schema.Types.Mixed, default: null },
  webhook_received:    { type: Boolean, default: false },
  processed:           { type: Boolean, default: false },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

module.exports = mongoose.model('Transaction', schema);