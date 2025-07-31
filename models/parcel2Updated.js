const mongoose = require("mongoose");

const ParcelSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  senderName: String,
  senderPhone: String,

  receiverName: String,
  receiverPhone: { type: String, required: true },

  description: String,
  type: { type: String, enum: ["document", "package", "gift", "other"], default: "package" },
  size: { type: String, enum: ["small", "medium", "large"], required: true },

  location_id: { type: mongoose.Schema.Types.ObjectId, ref: "DropLocation" }, // optional for tracking region
  lockerId: { type: String },                 // Actual drop locker
  compartmentId: { type: String },
  destinationLockerId: { type: String },      // Selected destination locker (optional)
  lockerLat: { type: String },
  lockerLng: { type: String },

  accessCode: { type: String, unique: true, required: true },
  qrImage: String,
  unlockUrl: String,

  razorpayOrderId: String,
  cost: { type: mongoose.Decimal128, default: 0, required: true },
  paymentOption: { type: String, enum: ["sender_pays", "receiver_pays"] },
  paymentStatus: { type: String, enum: ["pending", "completed"], default: "pending" },

    customId: {
    type: String,
    required: true,
    unique: true
  },

  store_self: {
  type: Boolean,
  default: false
},
razorpayPaymentLink: { type: String },
paymentStatus: { type: String, default: "pending" },


  status: {
    type: String,
    enum: [
      "awaiting_payment", // sender has not yet paid
      "awaiting_drop",    // waiting for sender to drop the parcel
      "awaiting_pick",    // receiver is yet to pick it up
      "in_transit",       // being moved by courier
      "picked",           // receiver has picked
      "expired"           // expired in locker
    ],
    default: "awaiting_payment"
  },

  transitInfo: {
    courier: String,
    courierCode: String,
    shiprocketCourierId: Number,
    fromLockerId: String,
    toLockerId: String,
    shiprocketOrderId: String,
    rate: mongoose.Decimal128,
    etd: String,
    startedAt: Date,
    deliveredAt: Date
  },

  shiprocketQuote: {
    courier_name: String,
    estimated_cost: Number,
    etd: String
  },


  receiverDeliveryMethod: { type: String, default: null },    // "courier" or "locker"
  recipientAddress: { type: String, default: null},
  recipientPincode : {type : String},
  selectedLocker : {type : String},
  selectedLockerPincode: {type : String},
  droppedAt: Date,
  pickedAt: Date,
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Parcel2", ParcelSchema);
