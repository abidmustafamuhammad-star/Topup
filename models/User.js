'use strict';
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username:          { type: String, required: true, unique: true, lowercase: true },
  email:             { type: String, required: true, unique: true, lowercase: true },
  password_hash:     { type: String, required: true },
  telegram_chat_id:  { type: String, default: null },
  telegram_username: { type: String, default: null },
  balance:           { type: Number, default: 0 },
  role:              { type: String, enum: ['user','admin'], default: 'user' },
  status:            { type: String, enum: ['active','suspended'], default: 'active' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

module.exports = mongoose.model('User', userSchema);