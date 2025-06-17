const express = require('express');
const app = express();
const Locker = require("./models/locker.js");
const port = 5000;


app.use(express.json());
// locker-device.js
const mqtt = require("mqtt");
const client = mqtt.connect("mqtt://broker.hivemq.com");

client.on("connect", () => {
  const lockerId = "L001";
  client.subscribe(`locker/unlock/${lockerId}/+`);
  console.log("Subscribed to unlock topic");
});

client.on("message", (topic, message) => {
  const [, , lockerId, compartmentId] = topic.split("/");
  const otpReceived = message.toString();

  // Validate OTP with internal cache or request server (optional)
  console.log(`🔓 Unlock request for ${lockerId}, Compartment ${compartmentId} with OTP ${otpReceived}`);
  
  // Trigger hardware to unlock
});

app.post("/unlock/:lockerId/:compartmentId", async (req, res) => {
  const { lockerId, compartmentId } = req.params;
  const { otp } = req.body;

  // 1. Validate OTP (your logic here)
  const locker = await Locker.findOne({ lockerId });
  const compartment = locker.compartments.find(c => c.compartmentId === compartmentId);

  if (compartment.bookingInfo.otp !== otp) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  // 2. Publish MQTT message
  mqttClient.publish(`locker/unlock/${lockerId}/${compartmentId}`, otp);
  res.json({ message: "Unlock signal sent" });
  console.log('message sent');
});



























app.listen(port,(req,res)=>{
    console.log(`listening on Port ${port}`);
})