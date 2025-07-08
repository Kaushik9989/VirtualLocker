const mongoose = require("mongoose");

const SessionIntentSchema = new mongoose.Schema({
  sessionId: String,
  userId: mongoose.Schema.Types.ObjectId,
  intent: String, // send, receive, explore
  startedAt: { type: Date, default: Date.now },
  completed: { type: Boolean, default: false },
  endedAt: Date
});

module.exports = mongoose.model("SessionIntent", SessionIntentSchema);
