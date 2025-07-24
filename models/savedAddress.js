const mongoose = require("mongoose");

const savedAddressSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  address: { type: String, required: true },
  pincode: { type: String, required: true },
  ownerName: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("SavedAddress", savedAddressSchema);
