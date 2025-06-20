const systemAlertSchema = new mongoose.Schema({
  type: { type: String, required: true }, // "locker_offline", "temp_alert"
  severity: { type: String, enum: ['low', 'medium', 'high'], default: 'low' },
  message: String,
  locker_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Locker' },
  acknowledged: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('SystemAlert', systemAlertSchema);
