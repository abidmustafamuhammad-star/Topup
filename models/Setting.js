'use strict';
const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  key:   { type: String, required: true, unique: true },
  value: { type: String, required: true },
}, { timestamps: { createdAt: false, updatedAt: 'updated_at' } });

module.exports = mongoose.model('Setting', schema);