const mongoose = require("mongoose");


const dropLocationSchema = new mongoose.Schema({
  name: { type: String, required: true },
  address: { type: String, required: true },
  latitude: mongoose.Decimal128,
  longitude: mongoose.Decimal128,
  totalLockers: { type: Number, default: 0 },
  operatingHours: {
    open: String,
    close: String
  },
  features: [String], // ["24/7", "guarded", "drive-thru"]
  services: [String],
  status: { type: String, default: 'active' }
});

module.exports = mongoose.model('DropLocation', dropLocationSchema);
