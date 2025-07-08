const mongoose = require("mongoose");

const StepDurationSchema = new mongoose.Schema({
  step: String,
  path: String,
  timestamp: Date,
  durationMs: Number,
  sessionId: String,
});

module.exports = mongoose.model("StepDuration", StepDurationSchema);
