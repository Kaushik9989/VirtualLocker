const mongoose = require("mongoose");

const courierSchema = new mongoose.Schema({
  phone: { type: String, required: true, unique: true },
  name: String,
  otp: String,
  otpVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Courier", courierSchema);
