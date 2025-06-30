const mongoose = require("mongoose");
const ParcelSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  lat : Number,
  lng : Number,
  senderName: String,
  receiverName: String,
  receiverPhone: String,
  lockerId: String,
  compartmentId: String,
  qrImage :String,
  status: { type: String, default: "Waiting for Pickup" },
  droppedAt: Date,
});

module.exports = mongoose.model("Parcel", ParcelSchema);
