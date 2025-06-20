const express = require("express");
const mongoose = require("mongoose");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bodyParser = require("body-parser");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const Locker = require("./models/locker.js");
const Locker1 = require("./models/Locker/LockerUpdated.js");
const DropLocation = require("./models/Locker/DropLocation.js");
const Parcel1 = require("./models/ParcelUpdated.js");
const User = require("./models/User/UserUpdated.js");
const Courier = require("./models/Courier.js");
const Parcel = require("./models/Parcel");
const app = express();
const PORT = 8080;
const Razorpay = require("razorpay");
const crypto = require("crypto");
const ejsMate = require("ejs-mate");
const flash = require("connect-flash");
const expressLayouts = require("express-ejs-layouts");
const MONGO_URI =
  "mongodb+srv://vivekkaushik2005:0OShH2EJiRwMSt4m@cluster0.vaqwvzd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const QRCode = require("qrcode");
require("dotenv").config();
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const locker = require("./models/locker.js");

require("dotenv").config();
const twilio = require("twilio");

const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

//const { client, serviceSid } = require("./twilio");

// const razorpay = new Razorpay({
//   key_id: process.env.RAZORPAY_KEY_ID,
//   key_secret: process.env.RAZORPAY_KEY_SECRET,
// });

app.engine("ejs", ejsMate); // Set ejs-mate as the EJS engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

app.use(
  session({
    secret: "heeeheheah", // replace with env var in prod
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: MONGO_URI,
      ttl: 60 * 60 * 24 * 7, // Session TTL in seconds (7 days)
    }),
    cookie: {
      maxAge: 30000 * 60 * 60 * 24, // 1 day
    },
  })
);

app.use(flash());

app.use((req, res, next) => {
  res.locals.messages = {
    success: req.flash("success"),
    error: req.flash("error"),
  };
  next();
});

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
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

// MIDDLEWARES

function isAuthenticated(req, res, next) {
  if (req.session.userId) return next();
  res.redirect("/login");
}

function isAdmin(req, res, next) {
  if (req.session.adminId) return next();
  res.redirect("/admin/login");
}

function isTechnincian(req, res, next) {
  if (req.session.techId) return next();
  res.redirect("/technician/login");
}

const isCourierAuthenticated = (req, res, next) => {
  if (req.session.courierId) return next();
  req.flash("error", "Please log in as a courier.");
  res.redirect("/courier/login");
};

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username });
      if (!user) return done(null, false, { message: "Incorrect username" });

      const isMatch = await user.comparePassword(password);
      if (!isMatch) return done(null, false, { message: "Incorrect password" });

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);
passport.use(
  new GoogleStrategy(
    {
      clientID:
        "587834679125-34p3obvnjoa9o8qsa4asgrgubneh5atg.apps.googleusercontent.com", // from Google Cloud
      clientSecret: "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", // from Google Cloud
      callbackURL: "https://virtuallocker.onrender.com/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      // Find or create user in DB
      const user = await User.findOne({ googleId: profile.id });
      if (user) return done(null, user);
      const newUser = new User({
        username: profile.displayName,
        googleId: profile.id,
        email: profile.emails[0].value,
      });
      await newUser.save();
      done(null, newUser);
    }
  )
);

app.get("/", (req, res) => {
  res.redirect("/dashboard");
});
//-------------------------------------USER DASHBOARD ------------------------------------------
app.get("/home", (req, res) => {
  if (req.isAuthenticated()) return res.render("LandingPage");
  res.redirect("/login");
});
app.get("/dashboard", isAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    const lockersRaw = await Locker.find({});

    const lockers = lockersRaw.map((locker) => ({
      lockerId: locker.lockerId,
      compartments: locker.compartments,
      location: locker.location || { lat: null, lng: null, address: "" },
    }));

    res.render("dashboard", { user, lockers });
  } catch (err) {
    console.error("Error loading dashboard:", err);
    res.status(500).send("Internal Server Error");
  }
});

// -------------------------------------------GOOGLE LOGIN ROUTES---------------------------------------------------

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Handle callback
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // Successful auth
    req.session.userId = req.user._id; // so your session-based auth also works
    res.redirect("/dashboard");
  }
);

// -------------------------------------------LOGIN ROUTES---------------------------------------------------

app.get("/login", (req, res) => {
  const error = req.query.error || null;
  res.render("login", { error });
});
app.post("/auth/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.redirect("/login?error=Invalid+username+or+password");

    req.logIn(user, (err) => {
      if (err) return next(err);
      req.session.userId = user._id;

      return res.redirect("/dashboard");
    });
  })(req, res, next);
});
app.get("/register", (req, res) => {
  const error = req.query.error || null;
  res.render("register", { error });
});

app.post("/auth/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const existing = await User.findOne({ username });
    if (existing) return res.redirect("/register?error=Username+already+taken");

    const user = new User({ username, password });
    await user.save();

    req.login(user, (err) => {
      if (err)
        return res
          .status(500)
          .json({ message: "Login error after registration" });
      res.redirect("/dashboard");
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err });
  }
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// -------------------------------------------LOGIN VIA OTP ROUTES---------------------------------------------------
// REGISTER VIA OTP

app.post("/register-send-otp", async (req, res) => {
  const { username, password, phone } = req.body;
  try {
    req.session.tempUser = { username, password, phone };

    await client.verify.v2
      .services(serviceSid)
      .verifications.create({ to: `+91${phone}`, channel: "sms" });

    res.redirect("/verify-register-otp");
  } catch (err) {
    console.error("Failed to send OTP:", err);
    res.status(500).send("Could not send OTP");
  }
});
app.get("/verify-register-otp", (req, res) => {
  res.render("verify-register-otp");
});

app.post("/verify-register-otp", async (req, res) => {
  const { otp } = req.body;
  const { username, password, phone } = req.session.tempUser || {};

  if (!username || !password || !phone) {
    return res.send("Session expired. Please register again.");
  }

  try {
    const verification = await client.verify.v2
      .services(serviceSid)
      .verificationChecks.create({ to: `+91${phone}`, code: otp });

    if (verification.status !== "approved") {
      return res.send("Incorrect OTP.");
    }

    const existing = await User.findOne({ phone });
    if (existing) return res.send("Phone already registered.");

    const newUser = new User({
      username,
      password,
      phone,
      isPhoneVerified: true,
    });
    await newUser.save();

    req.session.userId = newUser._id;
    res.redirect("/dashboard"); // or wherever you want
  } catch (err) {
    console.error(err);
    res.status(500).send("OTP verification failed");
  }
});

// LOGIN VIA OTP

app.post("/login-send-otp", async (req, res) => {
  const phone = req.body.phone;

  try {
    // Check if user with this phone exists
    const existingUser = await User.findOne({ phone });
    if (!existingUser) {
      return res.render("login", { error: "Phone number not registered." });
    }

    await client.verify.v2
      .services(serviceSid)
      .verifications.create({ to: `+91${phone}`, channel: "sms" });

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
    const verificationCheck = await client.verify.v2
      .services(serviceSid)
      .verificationChecks.create({ to: `+91${phone}`, code: otp });

    if (verificationCheck.status === "approved") {
      const user = await User.findOne({ phone });
      if (!user) {
        return res.render("verify-login-otp", {
          phone,
          error: "User not found.",
        });
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

// =------------------------------------------------CREDIT WALLET SECTION--------------------------------------------------\\
// GET: View wallet
app.get("/:id/credits", async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("wallet username");
    if (!user) return res.status(404).send("User not found");
    res.render("wallet/view", { user });
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// POST: Add credits
app.post("/:id/credits/add", async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).send("User not found");

    const numericAmount = parseInt(amount);
    if (isNaN(numericAmount) || numericAmount <= 0) {
      return res.status(400).send("Invalid amount");
    }

    user.wallet.credits += numericAmount;

    await user.save();
    req.flash("success", "Credits Added Successfully!!");
    res.redirect(`/${user._id}/credits`);
  } catch (err) {
    res.status(500).send("Server error");
  }
});

app.get("/map", async (req, res) => {
  try {
    const lockers = await Locker.find({});
    res.render("LockerMap", { lockers });
  } catch (err) {
    res.status(500).send("Failed to load lockers.");
  }
});

//// NEW LOCKER ROUTES

app.get("/send/step1", isAuthenticated, async (req, res) => {
  const lockers = await Locker1.find({ status: "available" }).populate(
    "location_id"
  );
  res.render("parcel/step1", { lockers });
});

app.post("/send/step1", isAuthenticated, async (req, res) => {
  try {
    const locker = await Locker1.findById(req.body.lockerId);
    if (!locker) return res.status(404).send("Locker not found");

    req.session.parcelDraft = {
      description: req.body.description,
      type: req.body.type,
      size: req.body.size,
      lockerId: req.body.lockerId,
      lockerBoxId : locker.lockerBoxId,  
      location_id: req.body.location_id,
      cost: locker.pricePerHour.toString(), // ✅ now defined
    };

    res.redirect("/send/step2");
  } catch (err) {
    console.error("Step 1 POST error:", err);
    res.status(500).send("Server error");
  }
});
app.get("/send/step2", isAuthenticated, (req, res) => {
  res.render("parcel/step2");
});
app.post("/send/step2", isAuthenticated, (req, res) => {
  req.session.parcelDraft.receiverName = req.body.receiverName;
  req.session.parcelDraft.receiverPhone = req.body.receiverPhone;
  res.redirect("/send/step3");
});

app.get("/send/step3", isAuthenticated, (req, res) => {
    if (!req.session.parcelDraft) return res.redirect("/send/step1");
  res.render("parcel/step3", { draft: req.session.parcelDraft });
});

app.post("/send/step3", isAuthenticated, async (req, res) => {
  const draft = req.session.parcelDraft;
  const accessCode = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
  const unlockUrl = `${req.protocol}://${req.get("host")}/unlock/${
    draft.lockerId
  }/${accessCode}`;
  const qrImage = await QRCode.toDataURL(unlockUrl);

  const parcel = new Parcel1({
    ...draft,
    senderId: req.user._id,
    senderName: req.user.username,
    accessCode,
    qrImage,
    cost: mongoose.Types.Decimal128.fromString(draft.cost.toString()),
    paymentOption: req.body.paymentOption,
    droppedAt: new Date(),
    expiresAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000), // 2 days
  });

  await parcel.save();

  // update locker status
  await Locker1.findByIdAndUpdate(draft.lockerId, {
    status: "occupied",
    isLocked: true,
  });

  delete req.session.parcelDraft;
  res.redirect(`/parcel/${parcel._id}/success`);
});

app.get("/parcel/:id/success", isAuthenticated, async (req, res) => {
  try {
    const parcel = await Parcel1.findById(req.params.id).populate(
      "location_id"
    ); // ✅ Only populate DropLocation

    if (
      !parcel ||
      !parcel.location_id ||
      !parcel.location_id.latitude ||
      !parcel.location_id.longitude
    ) {
      return res.status(404).send("Parcel or drop location not found.");
    }

    // Inject coordinates into the parcel object
    parcel.location = {
      lat: parcel.location_id.latitude,
      lng: parcel.location_id.longitude,
    };

    res.render("parcel/success", { parcel });
  } catch (err) {
    console.error("❌ Error loading parcel success:", err);
    res.status(500).send("Server error");
  }
});

app.get("/history", async (req, res) => {
  try {
    const parcels = await Parcel1.find({ senderId: req.user._id })
      .sort({ createdAt: -1 })
      .populate("location_id")
      .populate("lockerId");

    res.render("parcel/history", { parcels });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// -------------------------------------------- USER FUNCTIONS ----------------------------------------------------
app.get("/locker/directions/:lockerId/:compartmentId", async (req, res) => {
  const { lockerId, compartmentId } = req.params;
  const locker = await Locker.findOne({ lockerId });

  // For now just redirect to a dummy Google Maps link or custom UI
  res.redirect(
    `https://www.google.com/maps/dir/?api=1&destination=${locker.location.lat},${locker.location.lng}`
  );
});
app.get("/profile", isAuthenticated, async (req, res) => {
  try {
    const userId = req.user._id;

    const user = await User.findById(req.session.userId).populate("parcels");
    const allLockers = await Locker.find({
      "compartments.bookingInfo.userId": userId,
    });

    const bookings = [];

    for (const locker of allLockers) {
      for (const comp of locker.compartments) {
        if (comp.bookingInfo.userId?.toString() === userId.toString()) {
          bookings.push({
            lockerId: locker.lockerId,
            compartmentId: comp.compartmentId,
            bookingTime: comp.bookingInfo.bookingTime,
            isDelivered: comp.isDelivered || false,
            status: comp.isBooked ? "Booked" : "Completed",
          });
        }
      }
    }

    res.render("profile", { user, bookings });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

app.get("/locker/qr", isAuthenticated, async (req, res) => {
  const { lockerId, compartmentId, otp } = req.query;
  console.log("🔍 Incoming QR unlock request", req.query); // Debug

  const bookingData = {
    lockerId,
    compartmentId,
    otp,
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

app.get("/locker/:lockerId", async (req, res) => {
  const locker = await Locker.findOne({
    lockerId: req.params.lockerId,
  }).populate("compartments");
  if (!locker) return res.status(404).send("Locker not found");

  res.render("locker-details1", { locker, user: req.user });
});

app.post("/user/book", async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  const userId = req.session.userId; // Adjust to your auth logic

  try {
    const locker = await Locker.findById(lockerId);
    if (!locker) return res.status(404).send("Locker not found");

    const comp = locker.compartments.id(compartmentId);
    if (!comp || comp.isBooked)
      return res.status(400).send("Compartment unavailable");

    comp.isBooked = true;
    comp.bookingInfo = {
      userId,
      bookingTime: new Date(),
      otp: Math.floor(1000 + Math.random() * 9000).toString(),
    };

    await locker.save();
    res.redirect("/user/dashboard");
  } catch (err) {
    console.error(err);
    res.status(500).send("Booking failed");
  }
});

app.post("/locker/book", isAuthenticated, async (req, res) => {
  console.log("✅ /locker/book hit with:", req.body);
  const { lockerId, compartmentId } = req.body;
  try {
    const locker = await Locker.findOne({ lockerId });
    if (!locker) return res.status(404).send("Locker not found");

    const compartment = locker.compartments.find(
      (c) => c.compartmentId === compartmentId
    );
    if (!compartment || compartment.isBooked) {
      return res.status(400).send("Compartment already booked");
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    compartment.isBooked = true;
    compartment.isLocked = true;
    compartment.bookingInfo = {
      userId: req.session.userId,
      bookingTime: new Date(),
      otp,
    };
    const bookingData = {
      lockerId,
      compartmentId,
      otp,
    };

    const qrText = JSON.stringify(bookingData);
    const qrUrl = await QRCode.toDataURL(qrText);
    console.log(qrUrl);
    compartment.qrCode = qrUrl;

    await locker.save();

    // Redirect to QR display route
    res.redirect(
      `/locker/qr?lockerId=${lockerId}&compartmentId=${compartmentId}&otp=${otp}`
    );
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// -----------------------------------------------COURIERLOGIN ROUTES ------------------------------------------------
// GET - Courier Registration Page
app.get("/courier/register", (req, res) => {
  res.render("courierRegister", { message: req.flash("error") });
});

// POST - Register New Courier
app.post("/courier/register", async (req, res) => {
  const { name, phone } = req.body;

  try {
    const existing = await Courier.findOne({ phone });
    if (existing) {
      req.flash("error", "Courier already registered with this number.");
      return res.redirect("/courier/register");
    }

    const newCourier = new Courier({ name, phone });
    await newCourier.save();

    req.flash("success", "Registered successfully! Now login.");
    res.redirect("/courier/login");
  } catch (err) {
    console.error(err);
    req.flash("error", "Registration failed.");
    res.redirect("/courier/register");
  }
});

app.get("/courier/login", (req, res) => {
  res.render("courierLogin", { message: req.flash("error") });
});

app.post("/courier/login", async (req, res) => {
  const { phone, otp } = req.body;
  const courier = await Courier.findOne({ phone });

  if (!courier || courier.otp !== otp) {
    req.flash("error", "Invalid phone or OTP");
    return res.redirect("/courier/login");
  }

  req.session.courierId = courier._id;
  res.redirect("/courier/dashboard");
});

app.get("/courier/dashboard", async (req, res) => {
  const courierId = req.session.courierId;
  const lockers = await Locker.find({
    "compartments.bookingInfo.courierId": courierId,
  });

  const deliveries = [];

  lockers.forEach((locker) => {
    locker.compartments.forEach((comp) => {
      if (
        comp.bookingInfo.courierId?.toString() === courierId.toString() &&
        comp.isBooked &&
        comp.isLocked
      ) {
        deliveries.push({
          lockerId: locker.lockerId,
          compartmentId: comp.compartmentId,
          recipient: comp.bookingInfo.userId,
        });
      }
    });
  });

  res.render("courierDashboard", { deliveries });
});

app.post("/courier/deliver", async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  const locker = await Locker.findOne({ lockerId });

  const compartment = locker.compartments.find(
    (c) => c.compartmentId === compartmentId
  );

  if (!compartment || !compartment.isLocked) {
    req.flash("error", "Compartment not found or already unlocked");
    return res.redirect("/courier/dashboard");
  }

  // Unlock
  compartment.isLocked = false;
  await locker.save();

  req.flash(
    "success",
    `Compartment ${compartmentId} unlocked. Delivery successful.`
  );
  res.redirect("/courier/dashboard");
});

app.post("/courier/dropoff", isCourierAuthenticated, async (req, res) => {
  const { lockerId, compartmentId } = req.body;

  try {
    const locker = await Locker.findOne({ lockerId });

    if (!locker) {
      req.flash("error", "Locker not found.");
      return res.redirect("/courier/dashboard");
    }

    const compartment = locker.compartments.find(
      (c) => c.compartmentId === compartmentId
    );

    if (!compartment) {
      req.flash("error", "Invalid compartment.");
      return res.redirect("/courier/dashboard");
    }

    if (compartment.isBooked) {
      req.flash("error", "This compartment is already booked.");
      return res.redirect("/courier/dashboard");
    }

    // Simulate OTP generation (recipient will use this to unlock later)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    compartment.isBooked = true;
    compartment.isLocked = true;
    compartment.bookingInfo = {
      courierId: req.session.courierId,
      bookingTime: new Date(),
      otp,
    };

    await locker.save();

    req.flash(
      "success",
      `Package dropped successfully. OTP for pickup: ${otp}`
    );
    res.redirect("/courier/dashboard");
  } catch (err) {
    console.error(err);
    req.flash("error", "Failed to drop package.");
    res.redirect("/courier/dashboard");
  }
});

// ----------------------------------------------- LOCKER EMULATOR ---------------------------------------------------------

app.get("/locker/emulator/:lockerId", async (req, res) => {
  try {
    const locker = await Locker.findOne({ lockerId: req.params.lockerId });
    if (!locker) return res.status(404).json({ message: "Locker not found" });
    const compartments = locker.compartments;
    const { lockerId } = req.params;
    res.render("locker.ejs", { lockerId, compartments });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err });
  }
});

// Lock compartment
app.post("/locker/lock", async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  const locker = await Locker.findOne({ lockerId });
  if (!locker) return res.status(404).send("Locker not found");
  const compartment = locker.compartments.find(
    (c) => c.compartmentId === compartmentId
  );
  compartment.isLocked = true;
  await locker.save();
  res.redirect("/locker/emulator/" + lockerId);
});

// Unlock compartment (directly)
app.post("/locker/unlock-direct", async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  const locker = await Locker.findOne({ lockerId });
  if (!locker) return res.status(404).send("Locker not found");
  const compartment = locker.compartments.find(
    (c) => c.compartmentId === compartmentId
  );
  compartment.isLocked = false;
  await locker.save();
  res.redirect("/locker/emulator/" + lockerId);
});

// Send status
app.post("/locker/status", async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  const locker = await Locker.findOne({ lockerId });
  if (!locker) return res.status(404).send("Locker not found");
  const compartment = locker.compartments.find(
    (c) => c.compartmentId === compartmentId
  );
  console.log("-----------STATUS------------------");

  console.log(
    `Status Update: Locker ${lockerId}, Compartment ${compartmentId}, isLocked: ${compartment.isLocked}, isBooked: ${compartment.isBooked}`
  );
  res.redirect("/locker/emulator/" + lockerId);
});

app.post("/locker/unlock/:lockerId/:compartmentId", async (req, res) => {
  const { lockerId, compartmentId } = req.params;
  const locker = await Locker.findOne({ lockerId });
  if (!locker) {
    req.flash("error", "Locker Not found");
    return res.redirect("/locker/emulator/" + lockerId);
  }
  const compartment = locker.compartments.find(
    (c) => c.compartmentId === compartmentId
  );
  if (!compartment) {
    req.flash("error", "Compartment Not found");
    return res.redirect("/locker/emulator/" + lockerId);
  }

  const enteredOtp = req.body.otp;

  if (compartment.bookingInfo.otp === enteredOtp) {
    compartment.isLocked = false;
    compartment.isBooked = false;
    compartment.bookingInfo = {
      userId: null,
      bookingTime: null,
      otp: null,
    };

    // ✅ Tell Mongoose this nested path was modified
    locker.markModified("compartments");

    // ✅ Save the changes to DB
    await locker.save();
    console.log(`${compartmentId} is unlocked at Locker ${lockerId}`);
    req.flash(
      "success",
      `Locker ${compartmentId} has been unlocked successfully.`
    );
  } else {
    console.log("Unauthorized Access");
    req.flash("error", "Wrong OTP. Try again.");
  }

  res.redirect("/locker/emulator/" + lockerId);
});

app.get("/qrScan", (req, res) => {
  res.render("qrScan.ejs");
});
app.post("/unlock-via-qr-data", async (req, res) => {
  return res.json({ message: "Unlock Success" });
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

// ----------------------------------------------- LANDING PAGE (PICKUP OR DROP OFF) ROUTES --------------------------------------

app.get("/home", isAuthenticated, (req, res) => {
  res.render("LandingPage.ejs");
});

app.get("/user/pickup", (req, res) => {
  res.render("userPickup", { message: req.flash("error"), qrCode: null });
});
app.get("/user/pickup/self", async (req, res) => {
  const userId = req.session.userId;
  const selectedLockerId = req.query.lockerId || "";

  if (!userId) {
    req.flash("error", "Session expired. Please login again.");
    return res.redirect("/login");
  }

  const lockers = await Locker.find({
    "compartments.bookingInfo.userId": userId,
  });

  let compartments = [];

  lockers.forEach((locker) => {
    locker.compartments.forEach((compartment) => {
      if (
        compartment.bookingInfo &&
        compartment.bookingInfo.userId &&
        compartment.bookingInfo.userId.toString() === userId.toString()
      ) {
        if (!selectedLockerId || selectedLockerId === locker.lockerId) {
          compartments.push({
            lockerId: locker.lockerId,
            compartmentId: compartment.compartmentId,
            qrCode: compartment.qrCode,
          });
        }
      }
    });
  });

  // extract locker IDs for filter dropdown
  const lockerIds = [...new Set(lockers.map((l) => l.lockerId))];

  res.render("userPickupSelf", {
    compartments,
    lockerIds,
    selectedLockerId,
  });
});

app.get("/user/pickup/otp", async (req, res) => {
  const lockers = await Locker.find({ "compartments.isBooked": true });

  const bookedCompartments = [];

  lockers.forEach((locker) => {
    locker.compartments.forEach((comp) => {
      if (comp.isBooked && comp.isLocked) {
        bookedCompartments.push({
          lockerId: locker.lockerId,
          compartmentId: comp.compartmentId,
        });
      }
    });
  });

  res.render("userPickupOtp", {
    compartments: bookedCompartments,
    qrCode: null,
  });
});

app.post("/user/pickup/otp", async (req, res) => {
  const selected = req.body.selectedCompartment; // format: lockerId|compartmentId
  const otp = req.body.otp;

  const [lockerId, compartmentId] = selected.split("|");

  const locker = await Locker.findOne({ lockerId });
  if (!locker) {
    req.flash("error", "Locker not found");
    return res.redirect("/user/pickup/otp");
  }

  const compartment = locker.compartments.find(
    (c) => c.compartmentId === compartmentId
  );

  if (!compartment) {
    req.flash("error", "Invalid compartment ID");
    return res.redirect("/user/pickup/otp");
  }

  if (compartment.bookingInfo.otp === otp) {
    // ✅ Unlock
    compartment.isLocked = false;
    compartment.isBooked = false;

    await locker.save();

    req.flash("success", "✅ OTP verified! Compartment unlocked.");
    return res.redirect("/user/pickup/otp");
  } else {
    req.flash("error", "❌ Invalid OTP.");
    return res.redirect("/user/pickup/otp");
  }
});

app.get("/qr/:id", async (req, res) => {
  const parcel = await Parcel.findById(req.params.id);
  if (!parcel) return res.status(404).send("QR not found");

  res.render("qrMob", { qrImage: parcel.qrImage });
});

app.get("/user/dropoff", async (req, res) => {
  const userId = req.session.userId;

  if (!userId) {
    req.flash("error", "Session expired. Please login again.");
    return res.redirect("/login");
  }

  // Find lockers with compartments booked by this user
  const lockers = await Locker.find({
    "compartments.bookingInfo.userId": userId,
  });

  const compartments = [];

  lockers.forEach((locker) => {
    locker.compartments.forEach((compartment) => {
      if (
        compartment.isBooked &&
        compartment.isLocked &&
        compartment.bookingInfo?.userId?.toString() === userId.toString()
      ) {
        compartments.push({
          lockerId: locker.lockerId,
          compartmentId: compartment.compartmentId,
        });
      }
    });
  });

  if (compartments.length === 0) {
    req.flash("error", "No compartments booked or available for drop-off.");
    return res.redirect("/dashboard");
  }

  res.render("userDropoff", {
    compartments,
  });
});
app.post("/user/dropoff", async (req, res) => {
  const userId = req.session.userId;
  const user = await User.findById(req.session.userId);
  if (!userId) {
    req.flash("error", "Session expired. Please login again.");
    return res.redirect("/login");
  }
  try {
    const { lockerCompartment, receiverName, receiverPhone, otp } = req.body;
    const [lockerId, compartmentId] = lockerCompartment.split("|");

    const locker = await Locker.findOne({ lockerId });
    if (!locker) return res.status(404).send("Locker not found");

    const compartment = locker.compartments.find(
      (c) =>
        c.compartmentId === compartmentId &&
        c.bookingInfo?.userId?.toString() === userId.toString()
    );

    if (!compartment) {
      req.flash("error", "Compartment not found or not booked by you.");
      return res.redirect("/user/dropoff");
    }
    // Validate OTP
    if (compartment.bookingInfo.otp !== otp) {
      return res.status(400).send("Invalid OTP");
    }

    // Unlock logic (simulate only here)
    compartment.isLocked = false;
    compartment.isBooked = true;

    // Update receiver info
    compartment.bookingInfo = {
      bookingTime: new Date(),
      otp,
      receiverName,
      receiverPhone,
    };
    await locker.save();
    const bookingData = {
      lockerId,
      compartmentId,
      otp,
    };

    const qrText = JSON.stringify(bookingData);
    const qrImage = await QRCode.toDataURL(qrText);
    // Check if receiver is a user
    const newParcel = new Parcel({
      senderId: userId,
      senderName: user.username, // or name
      receiverName,
      receiverPhone,
      lockerId,
      compartmentId,
      qrImage,
      status: "Waiting for Pickup",
      droppedAt: new Date(),
    });

    await newParcel.save();
    const receiverUser = await User.findOne({ username: receiverName });
    // Push reference to the Parcel document
    receiverUser.parcels = receiverUser.parcels || [];
    receiverUser.parcels.push(newParcel._id);
    await receiverUser.save();
    //Send SMS to receiver
    const smsLink = `https://virtuallocker.onrender.com/qr/`;
    const message = await client.messages.create({
      body: `📦 Parcel dropped in Locker ${lockerId}, Compartment ${compartmentId} by ${user.username} \n OTP : ${otp}, Click Here to unlock via QR : ${smsLink}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: process.env.TO_PHONE_NUMBER, // Or `receiverPhone` if you verified that number too
    });
    console.log(
      `📦 Parcel dropped in Locker ${lockerId}, Compartment ${compartmentId} by ${user.username} \n OTP : ${otp}, Click Here to unlock via QR : ${smsLink}`
    );
    console.log("SMS sent:", message.sid);

    req.flash("success", "Compartment Unlocked, drop your parcel!!");
    res.redirect("/user/dropoff");
  } catch (err) {
    console.error(err);
    res.status(500).send("Something went wrong");
  }
});

// app.post("/user/dropoff", async (req, res) => {
//   const userId = req.session.userId;
//   const { lockerCompartment, otp } = req.body;

//   if (!userId) {
//     req.flash("error", "Session expired. Please login again.");
//     return res.redirect("/login");
//   }

//   const [lockerId, compartmentId] = lockerCompartment.split("|");

//   const locker = await Locker.findOne({ lockerId });

//   if (!locker) {
//     req.flash("error", "Locker not found.");
//     return res.redirect("/user/dropoff");
//   }

//   const compartment = locker.compartments.find(c =>
//     c.compartmentId === compartmentId &&
//     c.bookingInfo?.userId?.toString() === userId.toString()
//   );

//   if (!compartment) {
//     req.flash("error", "Compartment not found or not booked by you.");
//     return res.redirect("/user/dropoff");
//   }

//   if (compartment.bookingInfo.otp !== otp) {
//     req.flash("error", "Incorrect OTP.");
//     return res.redirect("/user/dropoff");
//   }

//   // ✅ Unlock the compartment
//   compartment.isLocked = false;
//   compartment.isBooked = false;
//   await locker.save();

//   req.flash("success", `Compartment ${compartmentId} unlocked successfully!`);
//   res.redirect("/user/dropoff");
// });

// ------------------------------------------------- ADMIN ROUTES ---------------------------------------------------------

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

// ADMIN
// Admin Login Page
app.get("/admin/login", (req, res) => {
  res.render("adminLogin", { error: null });
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
app.get("/admin/dashboard", isAdmin, async (req, res) => {
  try {
    const user = await User.findOne({ role: "admin" });
    const lockers = await Locker.find({});
    res.render("adminDashboard", { lockers, user });
  } catch (err) {
    console.error("❌ Error loading admin dashboard:", err);
    req.flash("error", "Failed to load dashboard.");
    res.redirect("/admin/login");
  }
});

app.get("/admin/add-locker", isAdmin, (req, res) => {
  res.render("add-locker");
});

app.get("/admin/bookings", isAdmin, async (req, res) => {
  const user = await User.findById(req.session.adminId);
  try {
    const lockers = await Locker.find({});
    const bookings = [];

    for (const locker of lockers) {
      for (const compartment of locker.compartments) {
        if (compartment.isBooked || compartment.bookingInfo.userId) {
          const user = await User.findById(
            compartment.bookingInfo.userId
          ).select("username");

          bookings.push({
            lockerId: locker.lockerId,
            compartmentId: compartment.compartmentId,
            username: user ? user.username : "Unknown",
            otp: compartment.bookingInfo.otp,
            bookingTime: compartment.bookingInfo.bookingTime,
            isLocked: compartment.isLocked,
          });
        }
      }
    }

    res.render("admin-bookings", { user, bookings });
  } catch (err) {
    res.status(500).send("Error fetching bookings");
  }
});

app.get("/admin/add-locker", isAdmin, async (req, res) => {
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
  const { lockerId, address, lat, lng } = req.body;
  const compartments = req.body.compartments || {};
  console.log("Locker ID:", req.body.lockerId);
  console.log("Compartments:", req.body.compartments);
  console.log("Address:", req.body.address);
  console.log("Lat:", req.body.lat);
  console.log("Lng:", req.body.lng);

  const compartmentArray = Object.values(compartments).map((c, i) => ({
    compartmentId: c.compartmentId || `C${i + 1}`,
    size: c.size || "medium",
    isBooked: false,
    isLocked: true,
    bookingInfo: {
      userId: null,
      bookingTime: null,
      otp: null,
    },
    qrCode: null,
  }));

  console.log("Final compartments:", compartmentArray); // ✅ debug

  const newLocker = new Locker({
    lockerId,
    location: { lat, lng, address },
    compartments: compartmentArray,
  });

  await newLocker.save();
  res.redirect("/admin/dashboard");
});

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
    const compartment = locker.compartments.find(
      (c) => c.compartmentId === compartmentId
    );
    if (compartment && compartment.isBooked) {
      compartment.isBooked = false;
      compartment.isLocked = true;
      compartment.qrCode = null;
      compartment.bookingInfo = {
        userId: null,
        otp: null,
        bookingTime: null,
      };
      await locker.save();
    }
    res.redirect("/admin/bookings");
  } catch (err) {
    res.status(500).send("Error cancelling booking");
  }
});

app.post("/locker/cancel", isAuthenticated, async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  try {
    const locker = await Locker.findOne({ lockerId });
    if (!locker) return res.status(404).send("Locker not found");

    const compartment = locker.compartments.find(
      (c) => c.compartmentId === compartmentId
    );
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
      otp: null,
    };

    await locker.save();
    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});
app.use((req, res, next) => {
  res.status(404).render("errorpage", { errorMessage: "Page Not Found (404)" });
});

// Admin Logout
app.get("/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/admin/login");
  });
});

// ---------------------------------------------------- TECHNICIAN ROUTES ------------------------------------------------------

app.get("/technician/login", (req, res) => {
  res.render("techLogin", { error: null });
});

app.post("/technician/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username, role: "technician" });
  if (!user || !(await user.comparePassword(password))) {
    return res.render("techLogin", { error: "Invalid credentials" });
  }

  res.redirect("/technician/dashboard");
});

app.get("/technician/dashboard", async (req, res) => {
  // <-- must be accessed ONLY ONCE
  res.render("addLockerTechnician");
});

// -------------------------------------------BACKEND MISCELLANEOUS ROUTES-----------------------------------------------------------

// app.get(
//   "/locker/access/:lockerId/:compartmentId",
//   isAuthenticated,
//   async (req, res) => {
//     const { lockerId, compartmentId } = req.params;
//     const locker = await Locker.findOne({ lockerId });

//     if (!locker) return res.status(404).send("Locker not found");

//     const compartment = locker.compartments.find(
//       (c) => c.compartmentId === compartmentId
//     );
//     if (!compartment) return res.status(404).send("Compartment not found");

//     if (compartment.isBooked) {
//       if (
//         compartment.bookingInfo.userId.toString() === req.user._id.toString()
//       ) {
//         // Authenticated and authorized
//         // Unlock the compartment (via MQTT or whatever system you use)
//         // You can also log access time
//         res.send("unlockSuccess");
//       } else {
//         return res
//           .status(403)
//           .send("Access Denied: You haven't booked this compartment.");
//       }
//     }
//     app.get(
//       "/locker/book/:lockerId/:compartmentId",
//       isAuthenticated,
//       async (req, res) => {
//         const { lockerId, compartmentId } = req.params;
//         // Show booking UI for the given compartment
//         res.send("bookYourCompartment");
//       }
//     );

//     // If not booked, redirect to booking page for this compartment
//     res.send("Not Booked");
//   }
// );
// app.get("/locker/status/:lockerId", async (req, res) => {
//   try {
//     const locker = await Locker.findOne({ lockerId: req.params.lockerId });
//     if (!locker) return res.status(404).json({ message: "Locker not found" });
//     res.json(locker);
//   } catch (err) {
//     res.status(500).json({ message: "Server error", error: err });
//   }
// });

// app.post("/locker/access", async (req, res) => {
//   const { lockerId, compartmentId, otp } = req.body;
//   try {
//     const locker = await Locker.findOne({ lockerId });
//     if (!locker) return res.status(404).json({ message: "Locker not found" });

//     const compartment = locker.compartments.find(
//       (c) => c.compartmentId === compartmentId
//     );
//     if (!compartment || !compartment.isBooked) {
//       return res
//         .status(400)
//         .json({ message: "Invalid or unbooked compartment" });
//     }

//     if (compartment.bookingInfo.otp !== otp) {
//       return res.status(401).json({ message: "Invalid OTP" });
//     }

//     compartment.isLocked = false;
//     await locker.save();
//     res.json({ message: "Compartment unlocked" });
//   } catch (err) {
//     res.status(500).json({ message: "Server error", error: err });
//   }
// });

/// ---------------------------------------------------PAYMENT ROUTES------------------------------------------------

// app.post("/payment/create-order", async (req, res) => {
//   const { lockerId, compartmentId } = req.body;

//   const options = {
//     amount: 5000, // ₹50 = 50 * 100 in paise
//     currency: "INR",
//     receipt: `receipt_${Date.now()}`,
//     payment_capture: 1,
//   };

//   try {
//     const response = await razorpay.orders.create(options);
//     res.render("paymentPage", {
//       key: process.env.RAZORPAY_KEY_ID,
//       order: response,
//       lockerId,
//       compartmentId,
//     });
//   } catch (err) {
//     console.error(err);
//     res.status(500).send("Error creating Razorpay order");
//   }
// });

// app.post("/payment/verify", async (req, res) => {
//   const {
//     razorpay_order_id,
//     razorpay_payment_id,
//     razorpay_signature,
//     lockerId,
//     compartmentId,
//   } = req.body;

//   const generatedSignature = crypto
//     .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
//     .update(`${razorpay_order_id}|${razorpay_payment_id}`)
//     .digest("hex");

//   if (generatedSignature === razorpay_signature) {
//     try {
//       const locker = await Locker.findOne({ lockerId });

//       const compartment = locker.compartments.find(
//         (c) => c.compartmentId === compartmentId
//       );

//       if (compartment) {
//         const otp = Math.floor(100000 + Math.random() * 900000).toString();

//         compartment.isBooked = true;
//         compartment.bookingInfo = {
//           userId: req.session.userId,
//           bookingTime: new Date(),
//           otp,
//         };

//         await locker.save();

//         return res.redirect(
//           `/locker/qr?lockerId=${lockerId}&compartmentId=${compartmentId}&otp=${otp}`
//         );
//       } else {
//         return res.status(404).send("Compartment not found");
//       }
//     } catch (error) {
//       console.error("Booking error:", error);
//       return res.status(500).send("Internal Server Error");
//     }
//   } else {
//     return res.status(400).send("Payment verification failed");
//   }
// });

// -------------------------------------------Error-handling middleware------------------------------------------------------
app.use((err, req, res, next) => {
  console.error(err.stack); // Log the error details (optional)
  res.status(500).render("errorpage", {
    errorMessage: err.message || "Internal Server Error",
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
