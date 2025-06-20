const mongoose = require('mongoose');

const lockerSchema = new mongoose.Schema({
  name: { type: String, required: true }, // Compartment name like "A1", "B3"
  
  lockerBoxId: { type: String, required: true }, // ID of the physical locker box this belongs to
  location_id: { type: mongoose.Schema.Types.ObjectId, ref: 'DropLocation', required: true },

  size: {
    type: String,
    enum: ['small', 'medium', 'large'],
    required: true
  },

  status: {
    type: String,
    enum: ['available', 'reserved', 'occupied', 'maintenance'],
    default: 'available'
  },

  isLocked: { type: Boolean, default: true },
  pricePerHour: { type: mongoose.Decimal128, default: 4.99 },

  // Booking Info (user booking the compartment)
  bookingInfo: {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    scheduledStart: Date,
    scheduledEnd: Date,
    actualStart: Date,
    actualEnd: Date,
    otp: { type: String, default: null },
    receiverName: { type: String, default: null },
    receiverPhone: { type: String, default: null }
  },

  // Courier Info (drop-off)
  courierInfo: {
    courierId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // must have courier role
    deliveryTime: Date
  },

  // Sensors and health info
  temperature: mongoose.Decimal128,
  humidity: mongoose.Decimal128,
  batteryLevel: Number,
  lastPing: Date,

  // Metadata
  qrCode: { type: String, default: null },
  features: [String], // e.g., ["temperature_control", "led_indicator"]

}, {
  timestamps: true
});

module.exports = mongoose.model('Locker1', lockerSchema);
