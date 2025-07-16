const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");
const { execSync } = require("child_process");

const Version = require("./models/Version"); // Your Mongoose schema

// Load MongoDB
mongoose.connect(process.env.MONGO_URI || "mongodb://localhost:27017/your-db");

// Get version
const version = JSON.parse(fs.readFileSync("version.json", "utf-8")).server;
const commitHash = execSync("git rev-parse HEAD").toString().trim();

// Create zip
const zipName = `release_${version}_${Date.now()}.zip`;
const zipPath = `backups\\${zipName}`;
execSync(`powershell.exe Compress-Archive -Path * -DestinationPath ${zipPath} -Force`);


(async () => {
  await Version.updateMany({}, { isCurrent: false });

  await Version.create({
    version,
    commitHash,
    pushedAt: new Date(),
    isCurrent: true,
    zipPath,
    deployedBy: process.env.USER || "local"
  });

  console.log(`✅ Version ${version} logged with commit ${commitHash}`);
  process.exit();
})();
