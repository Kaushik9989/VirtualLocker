const mongoose = require("mongoose");

const ParcelSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  senderName: { type: String },
  receiverName: { type: String },
  receiverPhone: { type: String, required: true },

  description: { type: String }, // now optional
  type: {
    type: String,
    enum: ["document", "package", "gift", "other"],
    required: true,
  },
  size: { type: String, enum: ["small", "medium", "large"], required: true },

  location_id: { type: mongoose.Schema.Types.ObjectId, ref: "DropLocation" }, // not required
  lockerId: { type: mongoose.Schema.Types.ObjectId, ref: "Locker" }, // not required

  accessCode: { type: String, unique: true, required: true },
  qrImage: { type: String },
  unlockUrl: { type: String },

  status: {
    type: String,
    enum: [
      "sent",
      "waiting",
      "delivered",
      "accepted",
      "declined",
      "expired",
      "awaiting_drop",
      "awaiting_payment",
    ],
    default: "awaiting_drop",
  },

  cost: { type: mongoose.Decimal128, required: true },
  paymentOption: {
    type: String,
    enum: ["sender_pays", "receiver_pays"],
    required: true,
  },
  paymentStatus: {
    type: String,
    enum: ["pending", "completed"],
    default: "pending",
  },

  droppedAt: Date,
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Parcel1", ParcelSchema);
