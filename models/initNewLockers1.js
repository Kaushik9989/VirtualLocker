const mongoose = require('mongoose');
const Locker1 = require('./Locker/LockerUpdated'); // Adjust path if necessary

// Replace with your actual MongoDB URI
const MONGODB_URI = 'mongodb+srv://vivekkaushik2005:0OShH2EJiRwMSt4m@cluster0.vaqwvzd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

async function initLockers() {
  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('Connected to MongoDB');

    // Clear existing lockers if needed
    await Locker1.deleteMany({});
    console.log('Old lockers removed');

    // Sample location and user ObjectIds
    const dummyLocationId = new mongoose.Types.ObjectId();
    const dummyUserId = new mongoose.Types.ObjectId();
    const dummyCourierId = new mongoose.Types.ObjectId();

    const lockers = [
      {
        name: 'A1',
        lockerBoxId: 'BOX001',
        location_id: dummyLocationId,
        size: 'small',
        status: 'available',
        isLocked: true,
        pricePerHour: 2.99,
        bookingInfo: {
          userId: dummyUserId,
          scheduledStart: new Date(),
          scheduledEnd: new Date(Date.now() + 2 * 60 * 60 * 1000), // 2 hours later
          actualStart: null,
          actualEnd: null,
          otp: '123456',
          receiverName: 'John Doe',
          receiverPhone: '9876543210'
        },
        courierInfo: {
          courierId: dummyCourierId,
          deliveryTime: new Date()
        },
        temperature: 22.5,
        humidity: 50.3,
        batteryLevel: 87,
        lastPing: new Date(),
        qrCode: 'QR-A1-001',
        features: ['temperature_control', 'led_indicator']
      },
      {
        name: 'B3',
        lockerBoxId: 'BOX002',
        location_id: dummyLocationId,
        size: 'medium',
        status: 'reserved',
        isLocked: false,
        pricePerHour: 3.49,
        bookingInfo: {
          userId: dummyUserId,
          scheduledStart: new Date(),
          scheduledEnd: new Date(Date.now() + 1 * 60 * 60 * 1000),
          actualStart: new Date(),
          actualEnd: null,
          otp: '789456',
          receiverName: 'Jane Smith',
          receiverPhone: '8765432109'
        },
        courierInfo: {
          courierId: dummyCourierId,
          deliveryTime: new Date()
        },
        temperature: 25.1,
        humidity: 55.2,
        batteryLevel: 73,
        lastPing: new Date(),
        qrCode: 'QR-B3-002',
        features: ['led_indicator']
      },
      {
        name: 'C2',
        lockerBoxId: 'BOX003',
        location_id: dummyLocationId,
        size: 'large',
        status: 'maintenance',
        isLocked: true,
        pricePerHour: 4.99,
        bookingInfo: {},
        courierInfo: {},
        temperature: 21.0,
        humidity: 48.6,
        batteryLevel: 90,
        lastPing: new Date(),
        qrCode: 'QR-C2-003',
        features: ['temperature_control']
      }
    ];

    await Locker1.insertMany(lockers);
    console.log('Lockers inserted successfully');
  } catch (error) {
    console.error('Error seeding lockers:', error);
  } finally {
    mongoose.connection.close();
  }
}

initLockers();
