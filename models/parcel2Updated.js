const mongoose = require("mongoose");

const ParcelSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  senderName: String,
  receiverName: String,
  lockerLat : {type : String},
  lockerLng : {type :String},
  senderPhone : {type: String},
  receiverPhone: { type: String, required: true },
  description: String,
  type: { type: String, enum: ["document", "package", "gift", "other"], default: "package" },
  size: { type: String, enum: ["small", "medium", "large"], required: true },
  location_id: { type: mongoose.Schema.Types.ObjectId, ref: "DropLocation" },
  lockerId: { type: String, required: false, default: null },
  compartmentId: { type: String },
  accessCode: { type: String, unique: true, required: true },
  qrImage: String,
  unlockUrl: String,
  razorpayOrderId : {type : String, },
 status: {
  type: String,
  enum: [
    "awaiting_payment",
    "awaiting_drop",
    "awaiting_pick",
    "picked",
    "expired",
    "in_transit", // ✅ added
  ],
  default: "awaiting_payment",
},
transitInfo: {
  courier: String,
  fromLockerId: String,
  toLockerId: String,
  startedAt: Date,
  deliveredAt: Date,
},
  cost: { type: mongoose.Decimal128, required: true, default : 0},
  paymentOption: { type: String, enum: ["sender_pays", "receiver_pays"], required: true },
  paymentStatus: { type: String, enum: ["pending", "completed"], default: "pending" },
  droppedAt: Date,
  pickedAt: Date,
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Parcel2", ParcelSchema);
