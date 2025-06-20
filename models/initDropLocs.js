const mongoose = require("mongoose");
const DropLocation = require("./Locker/DropLocation"); // Adjust path if needed

// MongoDB URI
const MONGODB_URI = 'mongodb+srv://vivekkaushik2005:0OShH2EJiRwMSt4m@cluster0.vaqwvzd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

async function initDropLocations() {
  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log("Connected to MongoDB");

    // Clear existing data (optional)
    await DropLocation.deleteMany({});
    console.log("Old drop locations removed");

    const locations = [
      {
        name: "City Center Mall",
        address: "123 Main Street, Downtown",
        latitude: 17.3850,
        longitude: 78.4867,
        totalLockers: 12,
        operatingHours: {
          open: "08:00",
          close: "22:00"
        },
        features: ["24/7", "guarded", "drive-thru"],
        services: ["parcel_pickup", "parcel_dropoff"],
        status: "active"
      },
      {
        name: "Tech Park Basement",
        address: "45 IT Hub Road, HITEC City",
        latitude: 17.4439,
        longitude: 78.3771,
        totalLockers: 20,
        operatingHours: {
          open: "06:00",
          close: "23:00"
        },
        features: ["guarded", "well-lit"],
        services: ["parcel_dropoff"],
        status: "active"
      },
      {
        name: "Airport Arrival Zone",
        address: "RGIA, Shamshabad",
        latitude: 17.2403,
        longitude: 78.4294,
        totalLockers: 30,
        operatingHours: {
          open: "00:00",
          close: "23:59"
        },
        features: ["24/7", "drive-thru"],
        services: ["parcel_pickup", "courier_booking"],
        status: "active"
      }
    ];

    await DropLocation.insertMany(locations);
    console.log("Drop locations inserted successfully");

    // Optional: Log inserted documents
    const all = await DropLocation.find({});
    console.log(all);

  } catch (error) {
    console.error("Error initializing drop locations:", error);
  } finally {
    mongoose.connection.close();
  }
}

initDropLocations();
