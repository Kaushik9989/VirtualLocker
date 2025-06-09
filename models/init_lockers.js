const mongoose = require('mongoose');
const Locker = require('./locker');

const MONGO_URI = 'mongodb://localhost:27017/virtualLocker'; 

mongoose.connect(MONGO_URI, { })
  .then(async () => {
    console.log('MongoDB connected.');

    await Locker.deleteMany(); // clean slate

    const lockers = [];

    for (let i = 1; i <= 3; i++) {
      const compartments = [];

      for (let j = 1; j <= 4; j++) {
        compartments.push({
          compartmentId: `L${i}-C${j}`,
        });
      }

      lockers.push({
        lockerId: `L${i}`,
        location: {
          lat: 17.385, 
          lng: 78.4867 + i * 0.01,
          address: `Area ${i}, Hyderabad`
        },
        compartments
      });
    }

    await Locker.insertMany(lockers);
    console.log('Lockers initialized!');
    mongoose.disconnect();
  })
  .catch(err => console.error(err));
