const parcel2Updated = require("./parcel2Updated");
const mongoose = require("mongoose");

const MONGO_URI =
  "mongodb+srv://vivekkaushik2005:0OShH2EJiRwMSt4m@cluster0.vaqwvzd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
  mongoose
    .connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB connected"))
    .catch((err) => console.error("❌ MongoDB connection error:", err));
async function backfillCustomIds() {
  const parcels = await parcel2Updated.find().sort({ createdAt: 1 });

  for (let i = 0; i < parcels.length; i++) {
    const p = parcels[i];
    const id = `P${String(i + 1).padStart(3, '0')}`;
    p.customId = id;

    try {
      await p.save();
      console.log(`Updated parcel ${p._id} with customId: ${id}`);
    } catch (err) {
      console.error(`Failed to update parcel ${p._id}:`, err.message);
    }
  }

  console.log("Backfill completed.");
}

backfillCustomIds();
