const mongoose = require('mongoose');
const Locker = require('./locker'); // adjust path if needed

const MONGO_URI = 'mongodb+srv://vivekkaushik2005:0OShH2EJiRwMSt4m@cluster0.vaqwvzd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

// Create 8 compartments
function generateCompartments() {
  const compartments = [];
  for (let i = 1; i <= 12; i++) {
    compartments.push({
      compartmentId: `C${i.toString().padStart(2, '0')}`,
      size: 'medium',
      isLocked: true,
      isBooked: false,
      currentParcelId: null,
      bookingInfo: {
        userId: null,
        bookingTime: null,
        otp: null,
        recieverName: null,
        recieverPhone: null
      },
      courierInfo: {
        courierId: null,
        deliveryTime: null
      },
      qrCode: null
    });
  }
  return compartments;
}

// Update all lockers with 8 compartments
async function updateAllLockers() {
  const lockers = await Locker.find();

  // Shuffle and select first 5 lockers
  const selectedLockers = lockers.sort(() => 0.5 - Math.random()).slice(0, 5);

  for (const locker of selectedLockers) {
    locker.compartments = generateCompartments(8); // 8 compartments
    await locker.save();
    console.log(`✅ Updated locker ${locker.lockerId} with 8 compartments`);
  }

  console.log('🎉 5 random lockers updated with 8 compartments.');
}


// Main execution
mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log('MongoDB connected.');
    await updateAllLockers();
    await mongoose.disconnect();
    console.log('MongoDB disconnected.');
  })
  .catch(console.error);
