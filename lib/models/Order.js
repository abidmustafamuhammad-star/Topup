'use strict';
const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  user_id:          { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  rumahotp_order_id:{ type: String, default: null },
  service_id:       { type: String, required: true },
  service_name:     { type: String, default: null },
  country:          { type: String, required: true },
  country_name:     { type: String, default: null },
  provider_id:      { type: String, default: null },
  operator_id:      { type: String, default: null },
  number_id:        { type: String, default: null },
  phone_number:     { type: String, default: null },
  otp_code:         { type: String, default: null },
  otp_message:      { type: String, default: null },
  base_price:       { type: Number, default: 0 },
  price:            { type: Number, default: 0 },
  status:           { type: String, enum: ['pending_payment','paid','number_issued','otp_received','completed','cancelled','expired'], default: 'pending_payment' },
  refunded:         { type: Boolean, default: false },
  expires_at:       { type: Date, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

module.exports = mongoose.model('Order', schema);
