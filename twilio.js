

const twilio = require("twilio");

const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

module.exports = {
  sendOTP: async (phone, otp) => {
    return client.messages.create({
      body: `Your DropPoint OTP is: ${otp}`,
      from: process.env.TWILIO_PHONE,
      to: phone,
    });
  },
};
