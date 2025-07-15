const mongoose = require("mongoose");

const versionSchema = new mongoose.Schema({
  version: String,
  date: { type: Date, default: Date.now },
  notes: String,
  pushedBy: String // optional: auto-fill from env or git config
});

module.exports = mongoose.model("Version", versionSchema);
