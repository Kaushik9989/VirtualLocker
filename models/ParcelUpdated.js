const mongoose = require("mongoose");

const ParcelSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  senderName: { type: String },
  
  receiverName: { type: String },
  receiverPhone: { type: String, required: true },

  description: { type: String, required: true }, // What’s being sent
  type: {
    type: String,
    enum: ['document', 'package', 'gift', 'other'],
    required: true
  },

  size: {
    type: String,
    enum: ['small', 'medium', 'large'],
    required: true
  },

  location_id: { type: mongoose.Schema.Types.ObjectId, ref: "DropLocation", required: true },
  lockerId: { type: mongoose.Schema.Types.ObjectId, ref: "Locker", required: true }, // each locker is a compartment in flat model

  accessCode: { type: String, unique: true, required: true }, // OTP / access code
  qrImage: { type: String }, // Can be a URL or base64

  status: {
    type: String,
    enum: ['sent', 'waiting', 'delivered', 'accepted', 'declined', 'expired'],
    default: 'sent'
  },

  cost: { type: mongoose.Decimal128, required: true },
  paymentOption: {
    type: String,
    enum: ['sender_pays', 'receiver_pays'],
    required: true
  },

  droppedAt: Date,
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Parcel1", ParcelSchema);
