const mongoose = require("mongoose");

const lockerBookingSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  locker_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Locker' },
  scheduledStart: { type: Date, required: true },
  scheduledEnd: { type: Date, required: true },
  actualStart: Date,
  actualEnd: Date,
  accessCode: { type: String, required: true, unique: true },
  cost: { type: mongoose.Decimal128, required: true },
  status: { type: String, default: 'reserved' },
  paymentStatus: { type: String, default: 'pending' }
});

module.exports = mongoose.model('LockerBooking', lockerBookingSchema);
