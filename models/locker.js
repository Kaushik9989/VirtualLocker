const mongoose = require('mongoose');

const CompartmentSchema = new mongoose.Schema({
  compartmentId: String,
  isLocked: { type: Boolean, default: true },
  isBooked: { type: Boolean, default: false },
  bookingInfo: {
    userId: { type: String, default: null },
    bookingTime: { type: Date, default: null },
    otp: { type: String, default: null }
  },
  qrCode : {type:String, default : null}
});


const LockerSchema = new mongoose.Schema({
  lockerId: { type: String, required: true, unique: true },
  location: {
    lat: { type: Number },
    lng: { type: Number },
    address: { type: String }
  },
  compartments: [CompartmentSchema]
})
// ❗️Make sure you're exporting the model here
module.exports = mongoose.model('Locker', LockerSchema);
