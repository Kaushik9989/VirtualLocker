const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String }, // not required for Google users or OTP users
  googleId: { type: String, unique: true, sparse: true },
  phone: { type: String, unique: true, sparse: true }, // for phone OTP users
  isPhoneVerified: { type: Boolean, default: false }, // flag for phone verification
  role: { type: String, enum: ['user', 'admin','technician'], default: 'user' },
  parcels: [{ type: mongoose.Schema.Types.ObjectId, ref: "Parcel" }],
});

// Hash password only if it's being set/modified
userSchema.pre("save", async function (next) {
  if (!this.isModified("password") || !this.password) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password
userSchema.methods.comparePassword = function (candidatePassword) {
  if (!this.password) return false; // avoid error for Google-only users
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model("User", userSchema);
