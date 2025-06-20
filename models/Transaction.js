const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: { type: String, required: true }, // payment, refund, topup
  amount: { type: mongoose.Decimal128, required: true },
  description: String,
  status: { type: String, default: 'pending' },
  service_type: String, // 'parcel' or 'locker_booking'
  service_id: { type: mongoose.Schema.Types.ObjectId },
  stripePaymentIntentId: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Transaction', transactionSchema);
