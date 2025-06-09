class Locker {
  constructor(id, totalCompartments = 5) {
    this.id = id;
    this.compartments = [];

    for (let i = 0; i < totalCompartments; i++) {
      this.compartments.push({
        id: `${id}-C${i + 1}`,
        isLocked: true,
        isBooked: false,
        bookingInfo: null,
      });
    }
  }

  getStatus() {
    return this.compartments.map(c => ({
      id: c.id,
      isLocked: c.isLocked,
      isBooked: c.isBooked,
    }));
  }

  bookCompartment(userId) {
    const comp = this.compartments.find(c => !c.isBooked);
    if (!comp) return null;

    comp.isBooked = true;
    comp.bookingInfo = {
      userId,
      bookingTime: new Date(),
      otp: Math.floor(100000 + Math.random() * 900000).toString(),
    };

    return {
      compartmentId: comp.id,
      otp: comp.bookingInfo.otp,
    };
  }

  accessCompartment(compartmentId, otp) {
    const comp = this.compartments.find(c => c.id === compartmentId);
    if (!comp || !comp.bookingInfo) return "Invalid compartment";

    if (comp.bookingInfo.otp !== otp) return "Invalid OTP";

    comp.isLocked = !comp.isLocked; // toggle lock
    return `Compartment ${comp.id} is now ${comp.isLocked ? 'locked' : 'unlocked'}`;
  }

  cancelBooking(compartmentId) {
    const comp = this.compartments.find(c => c.id === compartmentId);
    if (!comp || !comp.isBooked) return false;

    comp.isBooked = false;
    comp.isLocked = true;
    comp.bookingInfo = null;
    return true;
  }
}

module.exports = Locker;
