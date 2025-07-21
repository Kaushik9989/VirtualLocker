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
  courier: { type: String },                    // e.g., "Delhivery"
  courierCode: { type: String },                // e.g., "DLH"
  shiprocketCourierId: { type: Number },        // Optional: store courier_company_id from API
  fromLockerId: { type: String },
  toLockerId: { type: String },
  shiprocketOrderId: { type: String },          // If creating a full order via Shiprocket later
  rate: { type: mongoose.Decimal128 },          // Courier price
  etd: { type: String },                        // Estimated delivery time, like "2-3 days"
  startedAt: { type: Date },
  deliveredAt: { type: Date },
},
receiverDeliveryPending: { type: Boolean, default: false },
receiverFormToken: String, // for secure form link
receiverDeliveryMethod: { type: String,default: null },
receiverAddress: {
  addressLine: String,
  city: String,
  state: String,
  pincode: String,
  phone: String,
  name: String,
},
shiprocketQuote: {
  courier_name: String,
  estimated_cost: Number,
  etd: String
},
destinationLockerId: { type: String },
  cost: { type: mongoose.Decimal128, required: true, default : 0},
  paymentOption: { type: String, enum: ["sender_pays", "receiver_pays"], required: true },
  paymentStatus: { type: String, enum: ["pending", "completed"], default: "pending" },
  droppedAt: Date,
  pickedAt: Date,
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Parcel2", ParcelSchema);
