// models/Version.js
const mongoose = require("mongoose");

const versionSchema = new mongoose.Schema({
  version: String,                 // e.g. "1.0.7"
  commitHash: String,              // optional: Git SHA
  pushedAt: { type: Date, default: Date.now },
  isCurrent: { type: Boolean, default: false },
  zipPath: String,                 // path to zipped code for rollback
  deployedBy: String               // optional: dev username or ID
});

module.exports = mongoose.model("Version", versionSchema);
