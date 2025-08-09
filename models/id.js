const parcel2Updated = require("./parcel2Updated");
const mongoose = require("mongoose");
const Locker = require("./locker")
const MONGO_URI =
  "mongodb+srv://vivekkaushik2005:0OShH2EJiRwMSt4m@cluster0.vaqwvzd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
  mongoose
    .connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB connected"))
    .catch((err) => console.error("❌ MongoDB connection error:", err));

// Mongo shell script
(async () => {
  try {
    const lockers = await Locker.find({});

    for (const locker of lockers) {
      if (Array.isArray(locker.compartments)) {
        locker.compartments = locker.compartments.map((comp, index) => ({
          ...comp.toObject?.() ?? comp,  // Safely convert to plain object
          compartmentId: index.toString()
        }));

        await locker.save();
        console.log(`Updated locker ${locker.lockerId}`);
      } else {
        console.warn(`Locker ${locker.lockerId || locker._id} has no compartments array.`);
      }
    }

    console.log("All valid compartment IDs updated successfully.");
    mongoose.disconnect();
  } catch (err) {
    console.error("Error updating lockers:", err);
    mongoose.disconnect();
  }
})();