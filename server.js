const express = require("express");
const mongoose = require("mongoose");
const http = require('http');
const { Server } = require('socket.io');
const cors = require("cors");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bodyParser = require("body-parser");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const Locker = require("./models/locker.js");
const User = require("./models/User.js");
const app = express();
const PORT = 8080;
const ejsMate = require("ejs-mate");
const flash = require("connect-flash");
const expressLayouts = require("express-ejs-layouts");
app.engine("ejs", ejsMate); // Set ejs-mate as the EJS engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' } // Only for development/testing
});




io.on('connection', (socket) => {
  console.log('Client connected');

  socket.on('message', (message) => {
    console.log('Message received:', message);
    // Broadcast message to all clients
    io.emit('message', message);
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});










const MONGO_URI = "mongodb+srv://vivekkaushik2005:0OShH2EJiRwMSt4m@cluster0.vaqwvzd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const QRCode = require("qrcode");
require("dotenv").config();
const GoogleStrategy = require("passport-google-oauth20").Strategy; 
app.use(cors());
app.use(express.json()); 
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
const twilio = require("twilio");

// const accountSid = 'AC8875e19ba67aa60f0bd32d479b58c0b7';
// const authToken = 'c6953eaf1a5ad6c8334ec0c3b8669686';
// const serviceSid = 'VAe161a54de8168b204210a3855c5f51e5'; // Replace with your own if different

// const client = twilio(accountSid, authToken);

mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB connection error:", err));



app.use(session({
  secret: "yourSecretKey", // Use environment variable in production
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: MONGO_URI }),
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
    httpOnly: true
  }
}));
app.use(flash());
app.use((req, res, next) => {
  res.locals.success = req.flash("success");
  res.locals.error=req.flash("error");
  
  next();
});

app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user, done) => {
  done(null, user.id); // user._id
});

passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ username });
    if (!user) return done(null, false, { message: "Incorrect username" });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return done(null, false, { message: "Incorrect password" });

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));
passport.use(new GoogleStrategy({
    clientID: "587834679125-34p3obvnjoa9o8qsa4asgrgubneh5atg.apps.googleusercontent.com",         // from Google Cloud
    clientSecret: "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",  // from Google Cloud
    callbackURL: "https://virtuallocker.onrender.com/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    // Find or create user in DB
    const user = await User.findOne({ googleId: profile.id });
    if (user) return done(null, user);
    const newUser = new User({
      username: profile.displayName,
      googleId: profile.id,
      email: profile.emails[0].value
    });
    await newUser.save();
    done(null, newUser);
  }
));



app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);


// Handle callback
app.get("/auth/google/callback", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // Successful auth
    req.session.userId = req.user._id; // so your session-based auth also works
    res.redirect("/dashboard");
  }
);
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}


app.get("/", (req, res) => {
  if (req.isAuthenticated()) return res.redirect("/dashboard");
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  const error = req.query.error || null;
  res.render("login", { error });
});

app.get("/register", (req, res) => {
  const error = req.query.error || null;
  res.render("register", { error });
});

const { client, serviceSid } = require("./twilio");
app.post("/register-send-otp", async (req, res) => {
  const { username, password, phone } = req.body;
  try {
    req.session.tempUser = { username, password, phone };

    await client.verify.v2.services(serviceSid)
      .verifications.create({ to: `+91${phone}`, channel: 'sms' });
 
    res.redirect("/verify-register-otp");
  } catch (err) {
    console.error("Failed to send OTP:", err);
    res.status(500).send("Could not send OTP");
  }
});
app.get("/verify-register-otp", (req, res) => {
  res.render("verify-register-otp"); // assuming your EJS file is in views/
});

app.post("/verify-register-otp", async (req, res) => {
  const { otp } = req.body;
  const { username, password, phone } = req.session.tempUser || {};

  if (!username || !password || !phone) {
    return res.send("Session expired. Please register again.");
  }

  try {
    const verification = await client.verify.v2.services(serviceSid)
      .verificationChecks.create({ to: `+91${phone}`, code: otp });

    if (verification.status !== "approved") {
      return res.send("Incorrect OTP.");
    }

    const existing = await User.findOne({ phone });
    if (existing) return res.send("Phone already registered.");

    const newUser = new User({ username, password, phone, isPhoneVerified: true });
    await newUser.save();

    req.session.userId = newUser._id;
    res.redirect("/dashboard"); // or wherever you want
  } catch (err) {
    console.error(err);
    res.status(500).send("OTP verification failed");
  }
});


app.post("/login-send-otp", async (req, res) => {
  const phone = req.body.phone;

  try {
    // Check if user with this phone exists
    const existingUser = await User.findOne({ phone });
    if (!existingUser) {
      return res.render("login", { error: "Phone number not registered." });
    }

    await client.verify.v2.services(serviceSid)
      .verifications.create({ to: `+91${phone}`, channel: 'sms' });

    // Redirect to OTP verification page
    res.redirect(`/verify-login-otp?phone=${phone}`);
  } catch (err) {
    console.error("Error sending OTP:", err);
    res.render("login", { error: "Failed to send OTP. Try again." });
  }
});

app.get("/verify-login-otp", (req, res) => {
  const phone = req.query.phone;
  res.render("verify-login-otp", { phone, error: null });
});

app.post("/verify-login-otp", async (req, res, next) => {
  const { phone, otp } = req.body;

  try {
    const verificationCheck = await client.verify.v2.services(serviceSid)
      .verificationChecks.create({ to: `+91${phone}`, code: otp });

    if (verificationCheck.status === "approved") {
      const user = await User.findOne({ phone });
      if (!user) {
        return res.render("verify-login-otp", { phone, error: "User not found." });
      }

      // Log in the user using Passport
      req.logIn(user, (err) => {
        if (err) {
          console.error("Login error:", err);
          return next(err);
        }
        return res.redirect("/dashboard");
      });
    } else {
      return res.render("verify-login-otp", { phone, error: "Invalid OTP" });
    }
  } catch (err) {
    console.error("OTP verification error:", err);
    res.render("verify-login-otp", { phone, error: "Failed to verify OTP" });
  }
});
// Logout 
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});
app.get("/admin/add-locker",isAdmin,(req,res)=>{
  res.render("add-locker");
})
app.get("/dashboard", isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    const lockers = await Locker.find({});
    res.render("dashboard", { user, lockers });
  } catch (err) {
    res.status(500).send("Error loading dashboard");
  } 
});
// ADMIN
// Admin Login Page
app.get("/admin/login", (req, res) => {
  res.render("adminLogin", { error: null });
});
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});
// Admin Login Logic (basic auth)
app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username, role: "admin" });
  if (!user || !(await user.comparePassword(password))) {
    return res.render("adminLogin", { error: "Invalid credentials" });
  }
  req.session.adminId = user._id;
  res.redirect("/admin/dashboard");
});

app.get("/technician/login",(req,res)=>{
  res.render("techLogin",{error:null});
})

app.post("/technician/login",async(req,res)=>{
   const { username, password } = req.body;
  const user = await User.findOne({ username, role: "technician" });
  if (!user || !(await user.comparePassword(password))) {
    return res.render("techLogin", { error: "Invalid credentials" });
  }
  
  res.redirect("/technician/dashboard");

})

// Middleware to protect admin routes
function isAdmin(req, res, next) {
  if (req.session.adminId) return next();
  res.redirect("/admin/login");
}
function isTechnincian(req,res,next){
  if(req.session.techId) return next();
  res.redirect("/technician/login");
}
// Admin Register Page
app.get("/admin/register", (req, res) => {
  res.render("adminRegister", { error: null });
});

// Handle Admin Registration
app.post("/admin/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const existing = await User.findOne({ username });
    if (existing) {
      return res.render("adminRegister", { error: "Username already taken" });
    }

    const admin = new User({ username, password, role: "admin" });
    await admin.save();
    req.session.adminId = admin._id;

    res.redirect("/admin/dashboard");
  } catch (err) {
    res.status(500).send("Server error");
  }
});
// Admin Dashboard
app.get("/admin/dashboard", isAdmin, async (req, res) => {
  const user = await User.findById(req.session.adminId);
  const lockers = await Locker.find();
  res.render("adminDashboard", { user, lockers });
});

 app.get("/technician/dashboard", async (req, res) => {
  // <-- must be accessed ONLY ONCE
  res.render("addLockerTechnician", );
});
app.get("/admin/bookings", isAdmin, async (req, res) => {
  const user = await User.findById(req.session.adminId);
  try {
    const lockers = await Locker.find({});
    const bookings = [];

    for (const locker of lockers) {
      for (const compartment of locker.compartments) {
        if (compartment.isBooked && compartment.bookingInfo.userId) {
          const user = await User.findById(compartment.bookingInfo.userId).select("username");

          bookings.push({
            lockerId: locker.lockerId,
            compartmentId: compartment.compartmentId,
            username: user ? user.username : "Unknown",
            otp: compartment.bookingInfo.otp,
            bookingTime: compartment.bookingInfo.bookingTime,
            isLocked: compartment.isLocked
          });
        }
      }
    }

    res.render("admin-bookings", { user, bookings });
  } catch (err) {
    res.status(500).send("Error fetching bookings");
  }
});


app.get('/admin/add-locker', isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.session.adminId);
  res.render("add-locker", { user: user || { username: "Admin" } }); // ✅ FIXED path
  } catch (err) {
    console.error("Error rendering add-locker:", err);
    res.status(500).send("Internal server error");
  }
});

app.get("/admin/locker/:lockerId", isAdmin, async (req, res) => {
  try {
    const locker = await Locker.findOne({ lockerId: req.params.lockerId });
    if (!locker) return res.status(404).send("Locker not found");

    const user = await User.findById(req.session.adminId); // optional, if you need user info
    res.render("locker-details", { locker, user }); // Render the locker details view
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
  
});
app.post("/admin/add-locker", isAdmin, async (req, res) => {
  const { lockerId, totalCompartments, address, lat, lng } = req.body;

  // 1. Create compartments array
  const compartments = Array.from({ length: totalCompartments }).map((_, i) => ({
    compartmentId: `C${i + 1}`,
    isBooked: false,
    isLocked: true,
    bookingInfo: {  
      userId: null,
      bookingTime: null,
      otp: null
    },
    qrCode: null
  }));
  

  // 2. Create Locker document
  const newLocker = new Locker({
    lockerId,
    location: {
      lat : lat,
      lng : lng,
      address : address,
    },
    compartments
  });

  // 3. Generate QR codes
  for (let compartment of newLocker.compartments) {
    const qrUrl = `https://virtuallocker.onrender.com/locker/access/${lockerId}/${compartment.compartmentId}`;
    const qrDataUrl = await QRCode.toDataURL(qrUrl);
    compartment.qrCode = qrDataUrl;
    console.log(`✅ QR CREATED FOR LOCKER ${lockerId} COMPARTMENT ${compartment.compartmentId}`);
  }

  // 4. Save the updated locker with QR codes
  await newLocker.save();

  res.redirect("/admin/dashboard");
});
app.post("/technician/add-locker",async(req,res)=>{
    const { lockerId, totalCompartments, address, lat, lng } = req.body;

  // 1. Create compartments array
  const compartments = Array.from({ length: totalCompartments }).map((_, i) => ({
    compartmentId: `C${i + 1}`,
    isBooked: false,
    isLocked: true,
    bookingInfo: {  
      userId: null,
      bookingTime: null,
      otp: null
    },
    qrCode: null
  }));
  

  // 2. Create Locker document
  const newLocker = new Locker({
    lockerId,
    location: {
      lat : lat,
      lng : lng,
      address : address,
    },
    compartments
  });

  // 3. Generate QR codes
  for (let compartment of newLocker.compartments) {
    const qrUrl = `https://virtuallocker.onrender.com/locker/access/${lockerId}/${compartment.compartmentId}`;
    const qrDataUrl = await QRCode.toDataURL(qrUrl);
    compartment.qrCode = qrDataUrl;
    console.log(`✅ QR CREATED FOR LOCKER ${lockerId} COMPARTMENT ${compartment.compartmentId}`);
  }

  // 4. Save the updated locker with QR codes
  await newLocker.save();
  const message = "Locker Added!";
 
res.render("addLockerTechnician", {
  message: ["Locker Added!"]
});
  
})
app.post("/admin/delete-locker", async (req, res) => {
  const { lockerId } = req.body;
  try {
    await Locker.findOneAndDelete({ lockerId });
    res.redirect("/admin/dashboard");
  } catch (err) {
    res.status(500).send("Error deleting locker");
  }
});

app.post("/admin/cancel", isAdmin, async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  try {
    const locker = await Locker.findOne({ lockerId });
    const compartment = locker.compartments.find(c => c.compartmentId === compartmentId);
    if (compartment && compartment.isBooked) {
      compartment.isBooked = false;
      compartment.isLocked = true;
      compartment.bookingInfo = {
        userId: null,
        otp: null,
        bookingTime: null
      };
      await locker.save();
    }
    res.redirect("/admin/bookings");
  } catch (err) {
    res.status(500).send("Error cancelling booking");
  }
});

app.get("/locker/access/:lockerId/:compartmentId", isAuthenticated, async (req, res) => {
  const { lockerId, compartmentId } = req.params;
  const locker = await Locker.findOne({ lockerId });

  if (!locker) return res.status(404).send("Locker not found");

  const compartment = locker.compartments.find(c => c.compartmentId === compartmentId);
  if (!compartment) return res.status(404).send("Compartment not found");

  if (compartment.isBooked) {
    if (compartment.bookingInfo.userId.toString() === req.user._id.toString()) {
      // Authenticated and authorized
      // Unlock the compartment (via MQTT or whatever system you use)
      // You can also log access time
       res.send("unlockSuccess");
    } else {
      return res.status(403).send("Access Denied: You haven't booked this compartment.");
    }
  }
  app.get("/locker/book/:lockerId/:compartmentId", isAuthenticated, async (req, res) => {
  const { lockerId, compartmentId } = req.params;
  // Show booking UI for the given compartment
  res.send("bookYourCompartment");
});


  // If not booked, redirect to booking page for this compartment
   res.send("Not Booked");
});
// Admin Logout
app.get("/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/admin/login");
  });
});


app.post("/auth/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const existing = await User.findOne({ username });
    if (existing) return res.redirect("/register?error=Username+already+taken");


    const user = new User({ username, password });
    await user.save();

    req.login(user, (err) => {
      if (err) return res.status(500).json({ message: "Login error after registration" });
      res.redirect("/dashboard");
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err });
  }
});


app.get("/locker/emulatorWS/:lockerId",async(req,res)=>{
  try {
    const locker = await Locker.findOne({ lockerId: req.params.lockerId });
    if (!locker) return res.status(404).json({ message: "Locker not found" });
    const compartments = locker.compartments;
    const {lockerId} = req.params;
    res.render("lockerUsingWS.ejs",{lockerId,compartments});
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err });
  }
});





app.get("/locker/emulator/:lockerId",async(req,res)=>{
  try {
    const locker = await Locker.findOne({ lockerId: req.params.lockerId });
    if (!locker) return res.status(404).json({ message: "Locker not found" });
    const compartments = locker.compartments;
    const {lockerId} = req.params;
    res.render("locker.ejs",{lockerId,compartments});
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err });
  }
});


// Lock compartment
app.post('/locker/lock', async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  const locker = await Locker.findOne({ lockerId });
  if (!locker) return res.status(404).send('Locker not found');
  const compartment = locker.compartments.find(c => c.compartmentId === compartmentId);
  compartment.isLocked = true;
  await locker.save();
  res.redirect('/locker/emulator/' + lockerId);
});

// Unlock compartment (directly)
app.post('/locker/unlock-direct', async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  const locker = await Locker.findOne({ lockerId });
  if (!locker) return res.status(404).send('Locker not found');
  const compartment = locker.compartments.find(c => c.compartmentId === compartmentId);
  compartment.isLocked = false;
  await locker.save();
  res.redirect('/locker/emulator/' + lockerId);
});

// Send status
app.post('/locker/status', async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  const locker = await Locker.findOne({ lockerId });
  if (!locker) return res.status(404).send('Locker not found');
  const compartment = locker.compartments.find(c => c.compartmentId === compartmentId);
  console.log("-----------STATUS------------------")
  
  console.log(`Status Update: Locker ${lockerId}, Compartment ${compartmentId}, isLocked: ${compartment.isLocked}, isBooked: ${compartment.isBooked}`);
  res.redirect('/locker/emulator/' + lockerId);
});


app.post('/locker/unlock/:lockerId/:compartmentId', async (req, res) => {
  const { lockerId, compartmentId } = req.params;
  const locker = await Locker.findOne({ lockerId });
  if (!locker) {
    req.flash('error','Locker Not found');
    return res.redirect('/locker/emulator/' + lockerId);
  }
  const compartment = locker.compartments.find(c => c.compartmentId === compartmentId);
  if (!compartment)  {req.flash('error','Compartment Not found');
    return res.redirect('/locker/emulator/' + lockerId);}

  const enteredOtp = req.body.otp;

  if (compartment.bookingInfo.otp === enteredOtp) {
    compartment.isLocked = false;
    compartment.isBooked = false;
    compartment.bookingInfo = {
      userId: null,
      bookingTime: null,
      otp: null
    };

    // ✅ Tell Mongoose this nested path was modified
    locker.markModified('compartments');

    // ✅ Save the changes to DB
    await locker.save();
    console.log(`${compartmentId} is unlocked at Locker ${lockerId}`);
    req.flash('success', `Locker ${compartmentId} has been unlocked successfully.`);

    
  } else {
    
    console.log("Unauthorized Access");
    req.flash('error', 'Wrong OTP. Try again.');
  }

  res.redirect('/locker/emulator/' + lockerId);
});


app.post("/auth/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.redirect("/login?error=Invalid+username+or+password");

    req.logIn(user, err => {
      if (err) return next(err);
      return res.redirect("/dashboard");
    });
  })(req, res, next);
});



app.get("/auth/logout", (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.redirect("/login");
  });
});


app.get("/locker/status/:lockerId", async (req, res) => {
  try {
    const locker = await Locker.findOne({ lockerId: req.params.lockerId });
    if (!locker) return res.status(404).json({ message: "Locker not found" });
    res.json(locker);
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err });
  }
});


app.post("/locker/book", isAuthenticated, async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  try {
    const locker = await Locker.findOne({ lockerId });
    if (!locker) return res.status(404).send("Locker not found");

    const compartment = locker.compartments.find(c => c.compartmentId === compartmentId);
    if (!compartment || compartment.isBooked) {
      return res.status(400).send("Compartment already booked");
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();


    compartment.isBooked = true;
    compartment.isLocked = true;
    compartment.bookingInfo = {
      userId: req.user._id,
      bookingTime: new Date(),
      otp
    };

    await locker.save();

    // Redirect to QR display route
    res.redirect(`/locker/qr?lockerId=${lockerId}&compartmentId=${compartmentId}&otp=${otp}`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});
app.post("/locker/access", async (req, res) => {
  const { lockerId, compartmentId, otp } = req.body;
  try {
    const locker = await Locker.findOne({ lockerId });
    if (!locker) return res.status(404).json({ message: "Locker not found" });

    const compartment = locker.compartments.find(c => c.compartmentId === compartmentId);
    if (!compartment || !compartment.isBooked) {
      return res.status(400).json({ message: "Invalid or unbooked compartment" });
    }

    if (compartment.bookingInfo.otp !== otp) {
      return res.status(401).json({ message: "Invalid OTP" });
    }

    compartment.isLocked = false;
    await locker.save();
    res.json({ message: "Compartment unlocked" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err });
  }
});

app.get("/locker/qr", isAuthenticated, async (req, res) => {
  const { lockerId, compartmentId, otp } = req.query;

  const bookingData = {
    lockerId,
    compartmentId,
    otp
  };
  
  const qrText = JSON.stringify(bookingData);

  try {
    const qrUrl = await QRCode.toDataURL(qrText);
    
    res.render("qr", { qrUrl, bookingData });
  } catch (err) {
    console.error("QR Code generation error:", err);
    res.status(500).send("QR Code generation failed");
  }
});
app.get("/qrScan",(req,res)=>{
  res.render("qrScan.ejs");
})
app.post("/unlock-via-qr-data",async(req,res)=>{
   return res.json({ message: 'Unlock Success' });
});


app.post("/unlock-via-qr", async (req, res) => {
  const { lockerId, compartmentId, otp } = req.body;
  console.log("Unlock request via QR:", lockerId, compartmentId, otp);

  const locker = await Locker.findOne({ lockerId });
  if (!locker) {
    return res.status(404).json({ message: "Locker not found." });
  }

  const compartment = locker.compartments.find(
    (c) => c.compartmentId === compartmentId
  );

  if (!compartment) {
    return res.status(404).json({ message: "Compartment not found." });
  }

  if (compartment.bookingInfo.otp === otp) {
    compartment.isLocked = false;
    compartment.isBooked = false;
    compartment.bookingInfo = {
      userId: null,
      bookingTime: null,
      otp: null,
    };

    locker.markModified("compartments");
    await locker.save();

    console.log(`✅ ${compartmentId} is unlocked at Locker ${lockerId}`);
    return res.json({ message: "Locker unlocked successfully." });
  } else {
    console.log("❌ Wrong OTP.");
    return res.status(401).json({ message: "Wrong OTP." });
  }
});







app.post("/locker/cancel", isAuthenticated, async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  try {
    const locker = await Locker.findOne({ lockerId });
    if (!locker) return res.status(404).send("Locker not found");

    const compartment = locker.compartments.find(c => c.compartmentId === compartmentId);
    if (!compartment || !compartment.isBooked) {
      return res.status(400).send("No active booking found");
    }

    // Check if the user cancelling is the one who booked it
    if (compartment.bookingInfo.userId.toString() !== req.user._id.toString()) {
      return res.status(403).send("Unauthorized to cancel this booking");
    }

    // Cancel the booking
    compartment.isBooked = false;
    compartment.isLocked = true;
    compartment.bookingInfo = {
      userId: null,
      bookingTime: null,
      otp: null
    };

    await locker.save();
    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});
app.use((req, res, next) => {
  res.status(404).render('errorpage', { errorMessage: 'Page Not Found (404)' });
});

// Error-handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack); // Log the error details (optional)
  res.status(500).render('errorpage', { errorMessage: err.message || 'Internal Server Error' });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
