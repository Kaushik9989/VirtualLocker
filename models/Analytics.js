// models/Analytics.js
const mongoose = require('mongoose');

const analyticsSchema = new mongoose.Schema({
  type: String,
  timestamp: Date,
  path: String,
  tag: String,
  id: String,
  classes: String,
  text: String,
});

module.exports = mongoose.model('Analytics', analyticsSchema);
