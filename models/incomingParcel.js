const mongoose = require("mongoose");

const incomingParcelSchema = new mongoose.Schema({
  senderPhone: { type: String, required: true },
  receiverPhone: { type: String, required: true },
  receiverName: { type: String, default: "" },
  senderName : {type : String, default: ""},
  lockerId: { type: String, default: "" }, // in case it's assigned later

  status: {
    type: String,
   enum: ["awaiting_drop", "awaiting_pick", "picked", "expired"],
    default: "awaiting_drop",
  },
  lockerLat : {type :Number},
  lockerLng :{ type :Number},
  accessCode: { type: String, default: "" }, // for pickup
  qrCodeUrl: { type: String, default: "" },

  parcelType: { type: String, default: "general" },
  size: { type: String, default: "medium" },
  cost: { type: Number, default: 0 },

  metadata: {
    description: { type: String, default: "" },
    weight: { type: String, default: "" },
  },

  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("IncomingParcel", incomingParcelSchema);
