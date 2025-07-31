require("dotenv").config();
const twilio = require("twilio");

const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

client.verify.v2
  .services(process.env.TWILIO_VERIFY_SERVICE_SID)
  .verifications.create({
    to: "+916281672715", // put a valid number
    channel: "sms",
  })
  .then(res => console.log("OTP sent successfully:", res.sid))
  .catch(err => console.error("Twilio error:", err));
