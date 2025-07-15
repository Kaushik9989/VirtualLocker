const express = require("express");
const mongoose = require("mongoose");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const cors = require("cors");

const LRU = require("lru-cache");
const Razorpay = require("razorpay");



const locationsCache = new LRU.LRUCache({
  max: 10,
  ttl: 1000 * 60 * 5, // 5 min
});

const accountCache = new LRU.LRUCache({
  max: 500,
  ttl: 1000 * 60 * 2, // 2 min cache (you can adjust)
});
const uaParser = require("ua-parser-js");
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
const Parcel2 = require("./models/parcel2Updated.js");
const User = require("./models/User/UserUpdated.js");
const Courier = require("./models/Courier.js");
const Parcel = require("./models/Parcel");
const Analytics = require("./models/Analytics.js");
const SessionIntent = require("./models/sessionIntent.js");
const StepDuration = require("./models/stepDuration.js");
const incomingParcel = require("./models/incomingParcel.js");
const getGAStats = require('./utils/analytics');
const app = express();
const PORT = 8080;
const ejsMate = require("ejs-mate");
const flash = require("connect-flash");
const expressLayouts = require("express-ejs-layouts");
const MONGO_URI =
  "mongodb+srv://vivekkaushik2005:0OShH2EJiRwMSt4m@cluster0.vaqwvzd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const QRCode = require("qrcode");
require("dotenv").config();
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const { sendOTP } = require("./twilio.js");
const locker = require("./models/locker.js");
const compression = require("compression");
app.use(compression());
require("dotenv").config();

const server = http.createServer(app);
const io = new Server(server);

// Set up a cache for rendered HTML

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
app.use(express.static("public"));

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
app.use((req, res, next) => {
  // Track user intent only on main entry points
  if (req.path.startsWith("/send")) {
    setIntent(req, "send");
  } else if (req.path.startsWith("/receive")) {
    setIntent(req, "receive");
  } else if (req.path === "/") {
    setIntent(req, "explore");
  }
  next();
});
async function setIntent(req, intent) {
  const existing = await SessionIntent.findOne({ sessionId: req.sessionID, completed: false });
  if (!existing) {
    await SessionIntent.create({
      sessionId: req.sessionID,
      userId: req.session.user?._id || null,
      intent
    });
  }
}
app.use(flash());

app.use((req, res, next) => {
  res.locals.messages = {
    success: req.flash("success"),
    error: req.flash("error"),
  };
  next();
});
app.use((req, res, next) => {
  if (req.session.user) req.user = req.session.user;
  next();
});

app.use((req, res, next) => {
  if (req.session.user) req.user = req.session.user;
  next();
});
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});
app.use((req, res, next) => {
  if (req.session.user) {
    req.user = req.session.user;
  }
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
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || "your_key_id",
  key_secret: process.env.RAZORPAY_KEY_SECRET || "your_key_secret",
});
// // MIDDLEWARES
// app.use((req, res, next) => {
//   console.log("🌐", req.method, req.originalUrl);
//   console.log("🔐 Session user:", req.session.user);
//   console.log("➡️ redirectTo in session:", req.session.redirectTo);
//   next();
// });
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  }
  if (!req.session.redirectTo) {
    console.log("Saving redirectTo:", req.originalUrl);
    req.session.redirectTo = req.originalUrl;
  }

  return res.redirect("/login");
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
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      // callbackURL: "https://virtuallocker.onrender.com/auth/google/callback",
      // callbackURL:"http://localhost:8080/auth/google/callback",
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
// /api/sent-parcels
app.get("/api/sent-parcels", isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user._id).lean();
    if (!user) return res.status(401).json({ error: "Unauthorized" });

    const bookedParcels = await Parcel2.find({
      senderId: req.session.user._id,
    })
      .sort({ createdAt: -1 })
      .lean();

    res.json({ bookedParcels });
  } catch (err) {
    console.error("API sent parcels error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/analytics/step-duration", express.json(), async (req, res) => {
  const { step, durationMs, path, timestamp } = req.body;

  await StepDuration.create({
    step,
    durationMs,
    path,
    timestamp: new Date(timestamp),
    sessionId: req.sessionID
  });

  res.sendStatus(200);
});


app.get('/analytics', async (req, res) => {
  try {
    const data = await getGAStats();
    res.render('analytics', { data });
  } catch (error) {
    console.error('Analytics Error:', error);
    res.status(500).send('Failed to load analytics.');
  }
});

app.post('/track', async (req, res) => {
  try {
   
    await Analytics.create(req.body); // this will work if step 1 + 2 are right
    res.status(200).send("Tracked");
  } catch (err) {
    console.error("Tracking error:", err.message);
    res.sendStatus(500);
  }
});

app.get('/analytics/private', async (req, res) => {
  const data = await Analytics.find({}).lean();

  // Group by path
  const pathCounts = {};
  const tagCounts = {};
  const idCounts = {};

  data.forEach(item => {
    pathCounts[item.path] = (pathCounts[item.path] || 0) + 1;
    tagCounts[item.tag] = (tagCounts[item.tag] || 0) + 1;
    idCounts[item.id] = (idCounts[item.id] || 0) + 1;
  });

  res.render('adminAnal', {
    paths: Object.keys(pathCounts),
    pathData: Object.values(pathCounts),
    tags: Object.keys(tagCounts),
    tagData: Object.values(tagCounts),
    ids: Object.keys(idCounts),
    idData: Object.values(idCounts),
    raw: data
  });
});
// routes/api.js or directly in app.js
app.get("/api/track-send-click", async (req, res) => {
  try {
    
    await FunnelEvent.create({
      sessionId: req.sessionID,
      userId: req.user?._id || null,
      step: "send_parcel_clicked",
      timestamp: new Date()
    });
    res.sendStatus(204);
  } catch (err) {
    console.error("Send Parcel track failed:", err);
    res.sendStatus(500);
  }
});


app.post("/analytics/step-duration", async (req, res) => {
  const { step, durationMs, path, timestamp } = req.body;

  await StepDuration.create({
    step,
    durationMs,
    path,
    timestamp: new Date(timestamp),
    sessionId: req.sessionID
  });

  res.sendStatus(200);
});

app.get("/analytics/step-durations", async (req, res) => {
  const durations = await StepDuration.find().lean();

  const mapPathToStep = (path) => {
    if (!path) return null;
    if (path.includes("/send/step1")) return "send_step_1";
    if (path.includes("/send/step2")) return "send_step_2";
    if (path.includes("/send/step3")) return "send_step_3";
    if (path.includes("/payment")) return "payment";
    if (path.includes("/completed")) return "completed";
    return null;
  };

  const stepData = {};

  durations.forEach(entry => {
    let step = entry.step;
    if (!step) step = mapPathToStep(entry.path);

    if (!step) return; // skip unknown steps

    if (!stepData[step]) stepData[step] = [];
    stepData[step].push(entry.durationMs);
  });

  const stepAverages = Object.entries(stepData).map(([step, durations]) => ({
    step,
    avg: Math.round(durations.reduce((a, b) => a + b, 0) / durations.length)
  }));

  const orderedSteps = ["send_step_1", "send_step_2", "send_step_3", "payment", "completed"];

  const finalData = orderedSteps.map(name => {
    const match = stepAverages.find(e => e.step === name);
    return { step: name, avg: match ? match.avg : 0 };
  });

  res.render("step-durations", { durations: finalData });
});


app.get("/sendParcel", isAuthenticated, async (req, res) => {


  // Check cache firs
  try {
    const user = await User.findById(req.session.user._id);
    
    const bookedParcels = await Parcel2.find({
      senderId: req.session.user._id,
    }).sort({ createdAt: -1 });

    res.render(
      "sendParcel",
      {
        user: req.session.user,
        bookedParcels,
        activePage: "send",
      },
      (err, html) => {
        if (err) {
          console.error("Error rendering sendParcel:", err);
          return res.status(500).send("Internal Server Error");
        }

        // Store in cache
       

        res.send(html);
      }
    );
  } catch (err) {
    console.error("Error loading sendParcel:", err);
    res.status(500).send("Internal Server Error");
  }
  
}); // routes/api.js

// GET /api/lockers - Fetch all lockers and compartments
app.get("/lockers", async (req, res) => {
  try {
    const lockers = await Locker.find({});
    res.render("lockersNew", { lockers });
  } catch (err) {
    console.error("Error fetching lockers:", err);
    res.status(500).send("Error fetching lockers");
  }
});

// /api/locations
app.get("/api/locations", isAuthenticated, async (req, res) => {
  try {
    const lockersRaw = await Locker.find({}).lean();
    const locations = await DropLocation.find({ status: "active" }).lean();

    const enrichedLocations = locations.map((loc) => ({
      ...loc,
      distance: Math.floor(Math.random() * 20) + 1,
      rating: (Math.random() * 2 + 3).toFixed(1),
    }));

    const lockers = lockersRaw.map((locker) => ({
      lockerId: locker.lockerId,
      compartments: locker.compartments,
      location: locker.location || { lat: null, lng: null, address: "" },
    }));
    console.log("LOCKERSLCOATIONS SAVED TO LOCAL STORAGE");
    res.json({ lockers, enrichedLocations });
  } catch (err) {
    console.error("API locations error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/locations", isAuthenticated, async (req, res) => {
  const cacheKey = "locationsPage";
  console.log("location cache size: ", locationsCache.size);
  // Check cache
  const cachedHtml = locationsCache.get(cacheKey);
  if (cachedHtml) {
    console.log("✅ Served /locations from cache");
    return res.send(cachedHtml);
  }

  try {
    const lockersRaw = await Locker.find({}).lean();
    const locationsRaw = await DropLocation.find({ status: "active" }).lean();

    // Precompute enriched data only once
    const enrichedLocations = locationsRaw.map((loc) => ({
      ...loc,
      distance: Math.floor(Math.random() * 20) + 1,
      rating: (Math.random() * 2 + 3).toFixed(1),
    }));

    const lockers = lockersRaw.map((locker) => ({
      lockerId: locker.lockerId,
      compartments: locker.compartments,
      location: locker.location || { lat: null, lng: null, address: "" },
    }));

    res.render(
      "locations",
      {
        lockers,
        activePage: "locations",
        locations: enrichedLocations,
      },
      (err, html) => {
        if (err) {
          console.error("Error rendering locations:", err);
          return res.status(500).send("Internal Server Error");
        }

        // Cache HTML
        locationsCache.set(cacheKey, html);
        console.log("✅ Cached /locations HTML");

        res.send(html);
      }
    );
  } catch (err) {
    console.error("Error loading locations:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/receive", isAuthenticated, async (req, res) => {
  try {
    const userPhone = req.session.user.phone;

    const incomingParcels = await Parcel2.find({
      receiverPhone: userPhone
    }).sort({ createdAt: -1 });

    const filteredParcels = incomingParcels.filter(
      p => p.status === "awaiting_pick"
    );

    res.render("recieve", {
      parcels: filteredParcels,
      activePage: "receive",
      parcelCount: filteredParcels.length
    });
  } catch (error) {
    console.error("Error fetching parcels:", error);
    res.status(500).send("Server Error");
  }
});


/// accountCache.delete("account:" + req.session.user._id);
app.get("/account", isAuthenticated, async (req, res) => {
  const cacheKey = "account:" + req.session.user._id;

  // Check cache
  const cachedHtml = accountCache.get(cacheKey);
  if (cachedHtml) {
    console.log("✅ Served /account from cache for user", req.session.user._id);
    return res.send(cachedHtml);
  }

  try {
    const user = await User.findById(req.session.user._id).lean();

    res.render("account", { user, activePage: "account" }, (err, html) => {
      if (err) {
        console.error("Error rendering /account:", err);
        return res.status(500).send("Internal Server Error");
      }

      accountCache.set(cacheKey, html);
      console.log("✅ Cached /account HTML for user", req.session.user._id);

      res.send(html);
    });
  } catch (err) {
    console.error("Error loading /account:", err);
    res.status(500).send("Internal Server Error");
  }
});

async function notifyUserOnLockerBooking(
  receiverName,
  receiverPhone,
  accessCode,
  timestamp
) {
  try {
    const message = await client.messages.create({
      messagingServiceSid: process.env.TWILIO_MESSAGING_SERVICE_SID,
      to: `+91${receiverPhone}`, // e.g. "+919876543210"
      body: `📦 Hello ${receiverName}, a parcel has been sent to you via SmartLocker.\nAccess Code: ${accessCode}\nSent on: ${timestamp}`,
    });
    console.log("📤 SMS sent:", message.sid);
  } catch (err) {
    console.error("❌ Failed to send SMS:", err.message);
  }
}

app.get("/incoming/:id/qr", async (req, res) => {
  const parcel = await Parcel2.findById(req.params.id).lean();
  if (!parcel) return res.status(404).send("Parcel not found");
  if (!parcel.qrImage)
    return res.status(400).send("No QR code saved for this parcel");

  res.render("qrPage", { parcel });
});

//-------------------------------------USER DASHBOARD ------------------------------------------
app.get("/home", isAuthenticated, (req, res) => {
  if (req.isAuthenticated()) return res.render("LandingPage");
  res.redirect("/login");
});
app.get("/dashboard", isAuthenticated, async (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }

  try {
    const user = await User.findById(req.session.user._id).lean();
    if (!user) return res.redirect("/login");

    if (!user.phone) {
      req.flash(
        "error",
        "⚠️ Please link your phone number to receive parcel updates."
      );
    }

    // const lockersRaw = await Locker.find({});
    const userPhone = user.phone;
    const userName = user.username;

    // const incomingParcels = await incomingParcel.find({
    //   receiverPhone: userPhone,
    // }).sort({ createdAt: -1 });

    // const lockers = lockersRaw.map((locker) => ({
    //   lockerId: locker.lockerId,
    //   compartments: locker.compartments,
    //   location: locker.location || { lat: null, lng: null, address: "" },
    // }));

    // Render the EJS template to HTML string instead of sending immediately
     

    const incomingParcels = await Parcel2.find({
      receiverPhone: userPhone
    }).sort({ createdAt: -1 });

    const filteredParcels = incomingParcels.filter(
      p => p.status === "awaiting_pick"
    );
     await trackFunnelStep(req, "dashboard_loaded");
    res.render(
      "newDashboard",
      {
        user,

        activePage: "home",

        userName,
        parcelCount : filteredParcels.length
      },
     
    );
  } catch (err) {
    console.error("Error loading dashboard:", err);
    res.status(500).send("Internal Server Error");
  }
});

const FunnelEvent = require("./models/funnelEvent.js");

async function trackFunnelStep(req, step, metadata = {}) {
  try {
    const ua = uaParser(req.headers['user-agent']);
    const device = ua.device.type || 'desktop';

    await FunnelEvent.create({
      sessionId: req.sessionID,
      userId: req.user?._id || null,
      phone: req.body?.phone || null,
      step,
      metadata: {
        ...metadata,
        device
      }
    });
  } catch (err) {
    console.error("Funnel tracking error:", err);
  }
}
async function getAverageDurations() {
  const sessions = await FunnelEvent.aggregate([
    {
      $match: {
        step: { $in: [
          "visit_landing_page",
          "login_phone",
          "otp_entered",
          "dashboard_loaded",
          "send_parcel_clicked",
          "send_parcel_submitted",
          "parcel_created",
          "parcel_picked"
        ]}
      }
    },
    {
      $group: {
        _id: "$sessionId",
        steps: {
          $push: {
            step: "$step",
            timestamp: "$timestamp"
          }
        }
      }
    }
  ]);

  const durations = {
    loginToDashboard: [],
    sendStartToSubmit: [],
    parcelCreateToPickup: []
  };

  for (const session of sessions) {
    const stepMap = {};
    session.steps.forEach(e => stepMap[e.step] = new Date(e.timestamp));

    // Login → Dashboard
    if (stepMap["login_phone"] && stepMap["dashboard_loaded"]) {
      const delta = stepMap["dashboard_loaded"] - stepMap["login_phone"];
      if (delta >= 0 && delta <= 600000) durations.loginToDashboard.push(delta);
    }

    // Send Start → Submit
    if (stepMap["send_parcel_clicked"] && stepMap["send_parcel_submitted"]) {
      const delta = stepMap["send_parcel_submitted"] - stepMap["send_parcel_clicked"];
      if (delta >= 0 && delta <= 600000) durations.sendStartToSubmit.push(delta);
    }

    // Parcel Created → Pickup
    if (stepMap["parcel_created"] && stepMap["parcel_picked"]) {
      const delta = stepMap["parcel_picked"] - stepMap["parcel_created"];
      if (delta >= 0 && delta <= 24 * 60 * 60 * 1000) // < 24h
        durations.parcelCreateToPickup.push(delta);
    }
  }

  // Helper to compute avg
  const avg = arr =>
    arr.length ? (arr.reduce((a, b) => a + b, 0) / arr.length / 1000).toFixed(2) : "0.00";

  return {
    avgLoginToDashboard: avg(durations.loginToDashboard),
    avgSendFlow: avg(durations.sendStartToSubmit),
    avgPickupTime: avg(durations.parcelCreateToPickup)
  };
}


async function getStepDurations(sessionId) {
  const events = await FunnelEvent.find({ sessionId }).sort("timestamp");
  const steps = {};
  events.forEach(e => steps[e.step] = e.timestamp);

  const durations = {
    loginDelay: steps["login_phone"] && steps["visit_landing_page"]
      ? (steps["login_phone"] - steps["visit_landing_page"]) / 1000 : null,
    otpDelay: steps["otp_entered"] && steps["login_phone"]
      ? (steps["otp_entered"] - steps["login_phone"]) / 1000 : null,
    dashboardDelay: steps["dashboard_loaded"] && steps["otp_entered"]
      ? (steps["dashboard_loaded"] - steps["otp_entered"]) / 1000 : null,
  };

  return durations;
}

app.get("/admin/funnel", async (req, res) => {
 
        const timingData = await getAverageDurations();


        const loginPhoneCount = await FunnelEvent.distinct("sessionId", { step: "login_phone" }).then(d => d.length);
        const loginOAuthCount = await FunnelEvent.distinct("sessionId", { step: "login_oauth" }).then(d => d.length);


        const totalVisits   = await FunnelEvent.distinct("sessionId", { step: "visit_landing_page" }).then(d => d.length);
        const loginPhone    = await FunnelEvent.distinct("sessionId", { step: "login_phone" }).then(d => d.length);
        const otpEntered    = await FunnelEvent.distinct("sessionId", { step: "otp_entered" }).then(d => d.length);
        const dashboard     = await FunnelEvent.distinct("sessionId", { step: "dashboard_loaded" }).then(d => d.length);




        const drop1 = totalVisits - loginPhone;
        const drop2 = loginPhone - otpEntered;
        const drop3 = Math.max(otpEntered - dashboard, 0);

        const successRate = totalVisits > 0 ? ((dashboard / totalVisits) * 100).toFixed(2) : "0.00";


        const successRateNum = Math.min(parseFloat(successRate), 100);
        const abandonmentRate = (100 - successRateNum).toFixed(2);
        // Count distinct sessions per step
        const [visitSessions, loginSessions, otpSessions, dashboardSessions] = await Promise.all([
        FunnelEvent.distinct("sessionId", { step: "visit_landing_page" }),
        FunnelEvent.distinct("sessionId", { step: { $in: ["login_phone", "login_oauth"] } }),
        FunnelEvent.distinct("sessionId", { step: "otp_entered" }),
        FunnelEvent.distinct("sessionId", { step: "dashboard_loaded" })
        ]);

        // Count of users at each step
        const loginCount = loginSessions.length;
        const otpCount = otpSessions.length;
        const dashboardCount = dashboardSessions.length;

        // Drop-off at each step
        const dropAfterVisit = totalVisits - loginCount;
        const dropAfterLogin = loginCount - otpCount;
        const dropAfterOTP = Math.max(otpCount - dashboardCount, 0);

        const dashboardSession = await FunnelEvent.distinct("sessionId", { step: "dashboard_loaded" });
        const sendParcelSessions = await FunnelEvent.distinct("sessionId", { step: "send_parcel_clicked" });

        const sentCount = sendParcelSessions.length;
        const dashboardOnly = dashboardSessions.filter(id => !sendParcelSessions.includes(id));
        const notSentCount = dashboardOnly.length;
        // Stuck breakdown
        const stuckStats = {
        at_visit_page: dropAfterVisit,
        at_login: dropAfterLogin,
        at_otp: dropAfterOTP
        };
        res.render("funnelDashboard", {
        totalVisits,
        loginCount,
        otpCount,
        dashboardCount,
        successRate,
        abandonmentRate,
        stuckStats,
        timingData,
        loginPhone,
        otpEntered,
        dashboard,
        drop1,
        drop2,
        drop3,
        successRate,
        abandonmentRate,
        loginPhoneCount,
        sentCount,
        notSentCount,
        loginOAuthCount
        });
});


// app.get("/api/incoming-parcels", isAuthenticated, async (req, res) => {
//   try {
//     const userId = req.session.user._id;
//     const cacheKey = `incomingParcels:${userId}`;

//     // Check cache first
//     const cachedParcels = parcelCache.get(cacheKey);
//     if (cachedParcels) {
//       console.log("✅ Served incoming parcels from cache");
//       return res.json({ parcels: cachedParcels });
//     }

//     // No cache, fetch from DB
//     const user = await User.findById(userId).lean();
//     if (!user) return res.status(401).json({ error: "Unauthorized" });

//     const parcels = await incomingParcel.find({
//       receiverPhone: user.phone,
//     })
//       .sort({ createdAt: -1 })
//       .lean();

//     // Save to cache
//     parcelCache.set(cacheKey, parcels);

//     console.log("✅ Served incoming parcels from DB and cached");
//     res.json({ parcels });
//   } catch (err) {
//     console.error("API parcels error:", err);
//     res.status(500).json({ error: "Internal server error" });
//   }
// });

app.get("/api/lockers", isAuthenticated, async (req, res) => {
  try {
    const lockersRaw = await Locker.find({});
    const lockers = lockersRaw.map((locker) => ({
      lockerId: locker.lockerId,
      compartments: locker.compartments,
      location: locker.location || { lat: null, lng: null, address: "" },
    }));
    res.json({ lockers });
  } catch (err) {
    console.error("API lockers error:", err);
    res.status(500).json({ error: "Internal server error" });
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
  async (req, res) => {
    // Successful auth
    req.session.user = {
      _id: req.user._id,
      uid: req.user.uid,
      username: req.user.username,
      phone: req.user.phone,
      email: req.user.email,
      wallet: req.user.wallet || { credits: 0 },
      phone: req.user.phone || null,
    };
    await trackFunnelStep(req, "login_oauth", { phone: req.body.phone });
    const redirectTo = req.session.redirectTo || "/dashboard";
    delete req.session.redirectTo;

    return res.redirect(redirectTo); // so your session-based auth also works
  }
);

app.get("/link-phone", (req, res) => {
  res.render("link-phone", { error: null });
});
app.post("/link-phone", async (req, res) => {
  let rawPhone = req.body.phone || "";
  rawPhone = rawPhone.trim();

  // Normalize
  let phone = rawPhone;
  if (phone.startsWith("+91")) {
    phone = phone.slice(3);
  } else if (phone.startsWith("91")) {
    phone = phone.slice(2);
  } else if (phone.startsWith("0")) {
    phone = phone.slice(1);
  }

  // Now phone = "9123456789" (10-digit)
  if (phone.length !== 10) {
    return res.render("link-phone", {
      error: "❌ Please enter a valid 10-digit phone number.",
    });
  }

  // Store in canonical format: +91xxxxxxxxxx
  const canonicalPhone = "+91" + phone;

  // Check if already linked
  const existing = await User.findOne({ phone: canonicalPhone });
  if (existing && String(existing._id) !== String(req.session.user._id)) {
    return res.render("link-phone", {
      error: "❌ This phone number is already linked to another account.",
    });
  }

  try {
    await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({
        to: canonicalPhone,
        channel: "sms",
      });

    // Save to session
    req.session.linkPhone = phone;
    res.redirect("/verify-link-phone");
  } catch (err) {
    console.error("Failed to send OTP:", err);
    res.render("link-phone", { error: "❌ Could not send OTP. Try again." });
  }
});

app.get("/verify-link-phone", (req, res) => {
  res.render("verify-link-phone", { error: null });
});

app.post("/verify-link-phone", async (req, res) => {
  const { otp } = req.body;
  const phone = req.session.linkPhone;
  const canonicalPhone = `+91` + phone;
  try {
    const verificationCheck = await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({
        to: canonicalPhone,
        code: otp,
      });

    if (verificationCheck.status !== "approved") {
      return res.render("verify-link-phone", { error: "❌ Invalid OTP." });
    }

    const user = await User.findById(req.session.user._id);
    user.phone = phone;
    user.isPhoneVerified = true;
    await user.save();

    // Update session
    req.session.phone = phone;

    delete req.session.linkPhone;
    accountCache.delete("account:" + req.session.user._id);
    req.flash("success", "✅ Phone linked successfully.");
    res.redirect("/send/step1");
  } catch (err) {
    console.error("Error linking phone:", err);
    res.render("verify-link-phone", {
      error: "❌ Failed to verify. Try again.",
    });
  }
});

// -------------------------------------------LOGIN ROUTES---------------------------------------------------

app.get("/login", async(req, res) => {
   await trackFunnelStep(req, "visit_landing_page");
  const error = req.query.error || null;
  res.render("login", { error });
});
app.post("/auth/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.redirect("/login?error=Invalid+username+or+password");

    req.logIn(user, (err) => {
      if (err) return next(err);
      req.session.user = user._id;

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

app.use((req, res, next) => {
  if (req.session.user) {
    req.user = req.session.user;
  }
  next();
});

// -------------------------------------------LOGIN VIA OTP ROUTES---------------------------------------------------
// REGISTER VIA OTP

// Dependencies
const twilio = require("twilio");

const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

// Step 1: Phone Registration - Send OTP via Twilio Verify
app.post("/register-phone", async (req, res) => {
  const { phone } = req.body;
  req.session.phone = phone;

  try {
    await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({
        to: `+91${phone}`,
        channel: "sms",
      });
    console.log(`OTP sent to +91${phone}`);
    res.redirect("/verify");
  } catch (err) {
    console.error("Twilio Verify Error:", err.message);
    res.render("register", {
      error: "❌ Failed to send OTP. Check number and try again.",
    });
  }
});
app.get("/api/incoming-parcels", isAuthenticated, async (req, res) => {
  try {
    // Step 1: Find parcels
    const parcelsRaw = await Parcel2.find({
      receiverPhone: req.session.user.phone,
    })
      .sort({ createdAt: -1 })
      .select(
        "_id senderName metadata description type parcelType size cost accessCode status lockerId compartmentId qrCodeUrl expiresAt"
      );

    // Step 2: Extract unique lockerIds
    const lockerIds = [
      ...new Set(parcelsRaw.map((p) => p.lockerId).filter(Boolean)),
    ];

    // Step 3: Fetch lockers in bulk
    const lockersRaw = await Locker.find({
      lockerId: { $in: lockerIds },
    }).select("lockerId location");

    // Step 4: Build a map for quick lookup
    const lockerMap = new Map();
    lockersRaw.forEach((locker) => {
      lockerMap.set(locker.lockerId, locker);
    });

    // Step 5: Transform parcels and enrich with locker location
    const parcels = parcelsRaw.map((p) => {
      const locker = lockerMap.get(p.lockerId);
      return {
        _id: p._id,
        senderName: p.senderName,
        metadata: p.metadata,
        description: p.description,
        type: p.type,
        parcelType: p.parcelType,
        size: p.size,
        cost: p.cost?.toString() ?? null,
        accessCode: p.accessCode,
        status: p.status,
        lockerId: p.lockerId,
        compartmentId: p.compartmentId,
        qrCodeUrl: p.qrCodeUrl,
        expiresAt: p.expiresAt,
        lockerLocation: locker?.location
          ? {
              address: locker.location.address,
              latitude: locker.location.lat,
              longitude: locker.location.lng,
            }
          : null,
      };
    });

    // Respond
    res.json({
      success: true,
      parcels,
    });
  } catch (err) {
    console.error("Error fetching incoming parcels:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// Step 2: OTP Verification Page
app.get("/verify", (req, res) => {
  if (!req.session.phone) return res.redirect("/register");
  res.render("verify", { error: null });
});

// Step 3: Check OTP with Twilio Verify
app.post("/verify", async (req, res) => {
  const { otp } = req.body;
  const phone = req.session.phone;

  try {
    const verification = await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({
        to: `+91${phone}`,
        code: otp,
      });

    if (verification.status === "approved") {
      const existingUser = await User.findOne({ phone });
      if (existingUser) {
        // Already registered, log them in
        req.session.user = {
          _id: existingUser._id,
          uid: existingUser.uid,
          username: existingUser.username,
          phone: existingUser.phone,
          email: existingUser.email || null,
          wallet: existingUser.wallet || { credits: 0 },
        };
        delete req.session.phone;
        const redirectTo = req.session.redirectTo || "/dashboard";
        delete req.session.redirectTo;

        return res.redirect(redirectTo);
      }

      // New user - move to username setup
      return res.redirect("/set-username");
    } else {
      res.render("verify", { error: "❌ Incorrect OTP. Try again." });
    }
  } catch (err) {
    console.error("OTP Verification Error:", err.message);
    res.render("verify", { error: "❌ Could not verify OTP. Try again." });
  }
});

app.get("/set-username", (req, res) => {
  if (!req.session.phone) return res.redirect("/register");
  res.render("set-username", { error: null });
});

app.post("/set-username", async (req, res) => {
  const { username } = req.body;
  const phone = req.session.phone;

  try {
    // Check if username already exists
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.render("set-username", {
        error: "❌ Username already taken.",
      });
    }

    // Create new user
    const user = new User({
      phone,
      username,
      isPhoneVerified: true,
      uid: "user_" + Math.random().toString(36).substr(2, 9),
    });

    await user.save();

    // Set session user
    req.session.user = {
      _id: user._id,
      uid: user.uid,
      username: user.username,
      phone: user.phone,
      email: user.email || null,
      wallet: user.wallet || { credits: 0 },
    };

    // Clean up session
    delete req.session.phone;
    const redirectTo = req.session.redirectTo || "/dashboard";
    delete req.session.redirectTo;

    // 🚫 REMOVE this line - it is causing the error
    // req.user.phone = user.phone;
    accountCache.delete("account:" + req.session.user._id);
    res.redirect(redirectTo);
  } catch (err) {
    console.error("User Save Error:", err.message);
    res.render("set-username", {
      error: "❌ Failed to save user. Try again.",
    });
  }
});

app.post("/otpLogin", async (req, res) => {
  await trackFunnelStep(req, "login_phone", { phone: req.body.phone });
  const { phone } = req.body;

  // Check if user exists
  const user = await User.findOne({ phone });

  req.session.phone = phone;

  // Send OTP using Twilio Verify
  try {
    await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({
        to: `+91${phone}`,
        channel: "sms",
      });

    // If user exists, go to OTP verify page
    // If user doesn't exist, also go to OTP verify (we'll handle the check after OTP)
    res.redirect("/verify-login");
  } catch (err) {
    console.error("OTP send error:", err.message);
    res.render("login", { error: "❌ Failed to send OTP. Try again." });
  }
});

app.get("/verify-login", (req, res) => {
  if (!req.session.phone) return res.redirect("/login");
  res.render("verify-login", { error: null });
});

app.post("/verify-login", async (req, res) => {
  await trackFunnelStep(req, "otp_entered");
  
  // ...login logic


  const { otp } = req.body;
  const phone = req.session.phone;

  try {
    const verificationCheck = await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({
        to: `+91${phone}`,
        code: otp,
      });

    if (verificationCheck.status !== "approved") {
      return res.render("verify-login", {
        error: "❌ Invalid OTP. Try again.",
      });
    }

    let user = await User.findOne({ phone });

    if (!user) {
      // 👇 User doesn't exist, redirect to set-username
      return res.redirect("/set-username");
    }

    // ✅ Existing user
    req.session.user = {
      _id: user._id,
      uid: user.uid,
      username: user.username || null,
      phone: user.phone || null,
      email: user.email || null,
      wallet: user.wallet || { credits: 0 },
    };

    delete req.session.phone;
    res.redirect("/dashboard");
  } catch (err) {
    console.error("OTP Verify Error:", err.message);
    res.render("verify-login", { error: "❌ OTP verification failed." });
  }
});

app.get("/set-username", (req, res) => {
  if (!req.session.phone) return res.redirect("/login");
  res.render("set-username", { error: null });
});

app.post("/set-username", async (req, res) => {
  const { username } = req.body;
  const phone = req.session.phone;

  try {
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.render("set-username", {
        error: "❌ Username already taken.",
      });
    }

    const user = new User({
      phone,
      username,
      isPhoneVerified: true,
    });

    await user.save();

    req.session.user = {
      _id: user._id,
      uid: user.uid,
      username: user.username || null,
      phone: user.phone || null,
      email: user.email || null,
      wallet: user.wallet || { credits: 0 },
    };

    delete req.session.phone;
    res.redirect("/dashboard");
  } catch (err) {
    res.render("set-username", {
      error: "❌ Failed to save user.",
    });
  }
});

// =------------------------------------------------CREDIT WALLET SECTION--------------------------------------------------\\
// GET: View wallet
app.get("/:id/credits", isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("wallet username");
    if (!user) return res.status(404).send("User not found");
    res.render("wallet/view", { user });
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// POST: Add credits
app.post("/:id/credits/add", isAuthenticated, async (req, res) => {
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

/// updated locker flow

app.get("/send/step1", isAuthenticated, async (req, res) => {
  const user = await User.findById(req.session.user._id);
  console.log(user.phone);
  if (!user.phone) {
    req.flash(
      "error",
      "Please verify your phone number to continue sending a parcel."
    );
    return res.redirect("/link-phone");
  }
  res.render("parcel/step1", { messages: req.flash() });
  await SessionIntent.findOneAndUpdate(
  { sessionId: req.sessionID, completed: false },
  { completed: true, endedAt: new Date() }
);
});

app.post("/send/step1", isAuthenticated, (req, res) => {
  req.session.parcelDraft = {
    type: req.body.type,
    size: req.body.size,
    description: req.body.description || null,
  };
  res.redirect("/send/step2");
});

app.get("/send/step2", isAuthenticated, async(req, res) => {
  await FunnelEvent.create({
    sessionId: req.sessionID,
    userId: req.user?._id || null,
    step: "send_parcel_clicked",
    timestamp: new Date()
  });
   const user = await User.findById(req.session.user._id);
  console.log(user.phone);
  if (!user.phone) {
    req.flash(
      "error",
      "Please verify your phone number to continue sending a parcel."
    );
    return res.redirect("/link-phone");
  }
  const { size } = req.query;
  if (size) {
    // Initialize draft session if not present
    if (!req.session.parcelDraft) {
      req.session.parcelDraft = {};
    }
    req.session.parcelDraft.size = size;
    // Optionally, you could also set defaults:
    req.session.parcelDraft.type = "package";
    req.session.parcelDraft.description = "";
  }
  res.render("parcel/step2");
});

app.post("/send/step2", isAuthenticated, (req, res) => {
  req.session.parcelDraft.receiverName = req.body.receiverName;
  req.session.parcelDraft.receiverPhone = req.body.receiverPhone;
  res.redirect("/send/step3");
});
app.get("/send/step3", isAuthenticated, (req, res) => {
  res.render("parcel/step3");
  
});
function getEstimatedCost(size) {
  if (size === "small") return 10;
  if (size === "medium") return 20;
  return 30;
}
app.post("/send/step3", isAuthenticated, async (req, res) => {
  try {
    const draft = req.session.parcelDraft;
    draft.paymentOption = req.body.paymentOption;
    const user = await User.findById(req.session.user._id);
    const accessCode = Math.floor(100000 + Math.random() * 900000).toString();
    const cost = getEstimatedCost(draft.size).toString();
    const qrPayload = JSON.stringify({ accessCode });
    const qrImage = await QRCode.toDataURL(qrPayload);

    let status = "awaiting_drop";
    let paymentStatus = "completed";
    let expiresAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
    let razorpayOrder = null;

    if (draft.paymentOption === "sender_pays" || draft.paymentOption === "receiver_pays") {
      status = "awaiting_payment";
      paymentStatus = "pending";
      expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);
    }

    if (draft.paymentOption === "sender_pays") {
      razorpayOrder = await razorpay.orders.create({
        amount: parseFloat(cost) * 100,
        currency: "INR",
        receipt: `parcel_${Date.now()}`,
        payment_capture: 1,
      });
    }

    const parcel = new Parcel2({
      ...draft,
      senderId: req.user._id,
      senderName: req.user.username,
      accessCode,
      unlockUrl: null,
      qrImage,
      cost,
      status,
      paymentStatus,
      droppedAt: null,
      expiresAt,
      lockerId: null,
      compartmentId: null,
      razorpayOrderId: razorpayOrder?.id || null,
    });

    await parcel.save();
    delete req.session.parcelDraft;

    const updated = await incomingParcel.findOneAndUpdate(
      { receiverPhone: parcel.receiverPhone, status: "pending" },
      {
        receiverName: parcel.receiverName,
        parcelType: parcel.type,
        size: parcel.size,
        cost: parseFloat(parcel.cost),
        accessCode: parcel.accessCode,
        qrCodeUrl: parcel.qrImage,
        status: "awaiting_drop",
        lockerId: parcel.lockerId?.toString() || "",
        "metadata.description": parcel.description || "",
      },
      { new: true }
    );

    if (!updated) {
      await incomingParcel.create({
        senderPhone: user.phone || "unknown",
        receiverPhone: parcel.receiverPhone,
        senderName: user.username,
        receiverName: parcel.receiverName || "",
        parcelType: parcel.type,
        size: parcel.size,
        cost: parseFloat(parcel.cost),
        accessCode: parcel.accessCode,
        qrCodeUrl: parcel.qrImage,
        status: "awaiting_drop",
        lockerId: parcel.lockerId?.toString() || "",
        metadata: {
          description: parcel.description || "",
        },
        lockerLat: parcel.lockerLat,
        lockerLng: parcel.lockerLng,
      });
    }

    // ✅ WhatsApp Notification (before any return)
   


    // ✅ Funnel Event Logging
    await FunnelEvent.create({
      sessionId: req.sessionID,
      step: 'step3_complete',
      timestamp: new Date(),
    });

    // ✅ Now handle payment redirection
    if (draft.paymentOption === "receiver_pays") {
      return res.render("parcel/waiting-payment", { parcel });
    }

    if (draft.paymentOption === "sender_pays") {
      return res.render("parcel/payment", {
        parcel,
        razorpayKeyId: process.env.RAZORPAY_KEY_ID,
        orderId: razorpayOrder.id,
        amount: razorpayOrder.amount,
        currency: razorpayOrder.currency,
      });
    }

    // ✅ Final fallback redirect if payment is completed
    return res.redirect(`/parcel/${parcel._id}/success`);

  } catch (error) {
    console.error("❌ Error in /send/step3:", error);
    req.flash("error", "An unexpected error occurred. Please try again.");
    res.redirect("/dashboard");
  }
});


// app.post("/send/step3", isAuthenticated, async (req, res) => {
//   try {
//     const draft = req.session.parcelDraft;
//     draft.paymentOption = req.body.paymentOption;
//     const user = await User.findById(req.session.user._id);
//     const accessCode = Math.floor(100000 + Math.random() * 900000).toString();
//     const cost = getEstimatedCost(draft.size).toString();
//     const qrPayload = JSON.stringify({
//       accessCode: accessCode,
//     });
//     const qrImage = await QRCode.toDataURL(qrPayload);

//     let status = "awaiting_drop";
//     let paymentStatus = "completed";
//     let expiresAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
//     let razorpayOrder = null;

//     if (draft.paymentOption === "sender_pays") {
//       // Create Razorpay order
//       razorpayOrder = await razorpay.orders.create({
//         amount: parseFloat(cost) * 100,
//         currency: "INR",
//         receipt: `parcel_${Date.now()}`,
//         payment_capture: 1,
//       });
//       status = "awaiting_payment";
//       paymentStatus = "pending";
//       expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);
//     } else if (draft.paymentOption === "receiver_pays") {
//       status = "awaiting_payment";
//       paymentStatus = "pending";
//       expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);
//     }

//     const parcel = new Parcel2({
//       ...draft,
//       senderId: req.user._id,
//       senderName: req.user.username,
//       accessCode,
//       unlockUrl: null,
//       qrImage,
//       cost,
//       status,
//       paymentStatus,
//       droppedAt: null,
//       expiresAt,
//       lockerId: null,
//       compartmentId: null,
//       razorpayOrderId: razorpayOrder?.id || null,
//     });

//     await parcel.save();
//     delete req.session.parcelDraft;

//     const updated = await incomingParcel.findOneAndUpdate(
//       { receiverPhone: parcel.receiverPhone, status: "pending" },
//       {
//         receiverName: parcel.receiverName,
//         parcelType: parcel.type,
//         size: parcel.size,
//         cost: parseFloat(parcel.cost),
//         accessCode: parcel.accessCode,
//         qrCodeUrl: parcel.qrImage,
//         status: "awaiting_drop",
//         lockerId: parcel.lockerId?.toString() || "",
//         "metadata.description": parcel.description || "",
//       },
//       { new: true }
//     );

//     if (!updated) {
//       await incomingParcel.create({
//         senderPhone: user.phone || "unknown",
//         receiverPhone: parcel.receiverPhone,
//         senderName: user.username,
//         receiverName: parcel.receiverName || "",
//         parcelType: parcel.type,
//         size: parcel.size,
//         cost: parseFloat(parcel.cost),
//         accessCode: parcel.accessCode,
//         qrCodeUrl: parcel.qrImage,
//         status: "awaiting_drop",
//         lockerId: parcel.lockerId?.toString() || "",
//         metadata: {
//           description: parcel.description || "",
//         },
//         lockerLat: parcel.lockerLat,
//         lockerLng: parcel.lockerLng,
//       });
//     }

//     if (draft.paymentOption === "receiver_pays") {
//       return res.render("parcel/waiting-payment", { parcel });
//     }

//     if (draft.paymentOption === "sender_pays") {
//       return res.render("parcel/payment", {
//         parcel,
//         razorpayKeyId: process.env.RAZORPAY_KEY_ID,
//         orderId: razorpayOrder.id,
//         amount: razorpayOrder.amount,
//         currency: razorpayOrder.currency,
//       });
//     }
//     client.messages
//   .create({
//     from: 'whatsapp:+15558076515', // Twilio's sandbox or your approved number
//     to: `whatsapp:+91${user.phone}`, // User's WhatsApp number
//     body: 'Your Parcel has been booked, Please go to your nearest locker to place it!',
//   })
//   .then(message => console.log('Message sent:',message.sid))
//   .catch(error => console.error('Error:', error));
// await FunnelEvent.create({
//   sessionId: req.sessionID,
//   step,
//   timestamp: new Date(),
// });
    
//     res.redirect(`/parcel/${parcel._id}/success`);
//   } catch (error) {
//     console.error("Error in /send/step3:", error);
//     req.flash("error", "An unexpected error occurred. Please try again.");
//     res.redirect("/dashboard");
//   }
// });

// app.post("/send/step3", isAuthenticated, async (req, res) => {
//   const draft = req.session.parcelDraft;
//   draft.paymentOption = req.body.paymentOption;
//   const user = await User.findById(req.session.user._id);
//   const accessCode = Math.floor(100000 + Math.random() * 900000).toString();
//   const cost = getEstimatedCost(draft.size).toString();
//   const qrPayload = JSON.stringify({
//     accessCode: accessCode,
//   });
//   const qrImage = await QRCode.toDataURL(qrPayload);
//   const status =
//     draft.paymentOption === "receiver_pays"
//       ? "awaiting_payment"
//       : "awaiting_drop";
//   const paymentStatus =
//     draft.paymentOption === "receiver_pays" ? "pending" : "completed";
//   const droppedAt = null;
//   const expiresAt =
//     draft.paymentOption === "receiver_pays"
//       ? new Date(Date.now() + 2 * 60 * 60 * 1000)
//       : new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);

//   const parcel = new Parcel2({
//     ...draft,
//     senderId: req.user._id,
//     senderName: req.user.username,
//     accessCode,
//     unlockUrl: null,
//     qrImage,
//     cost,
//     status,
//     paymentStatus,
//     droppedAt,
//     expiresAt,
//     lockerId: null,
//     compartmentId: null,
//   });

//   await parcel.save();
//   delete req.session.parcelDraft;

//   // ✅ Sync with IncomingParcel
//   const updated = await incomingParcel.findOneAndUpdate(
//     {
//       receiverPhone: parcel.receiverPhone,
//       status: "pending",
//     },
//     {
//       receiverName: parcel.receiverName,
//       parcelType: parcel.type,
//       size: parcel.size,
//       cost: parseFloat(parcel.cost.toString()),
//       accessCode: parcel.accessCode,
//       qrCodeUrl: parcel.qrImage,
//       status: "awaiting_drop", // Corrected
//       lockerId: parcel.lockerId?.toString() || "",
//       "metadata.description": parcel.description || "",
//     },
//     { new: true }
//   );

//   // ✅ If no matching incoming parcel found, create new
//   if (!updated) {
//     await incomingParcel.create({
//       senderPhone: user.phone || "unknown",
//       receiverPhone: parcel.receiverPhone,
//       senderName: user.username,
//       receiverName: parcel.receiverName || "",
//       parcelType: parcel.type,
//       size: parcel.size,
//       cost: parseFloat(parcel.cost.toString()),
//       accessCode: parcel.accessCode,
//       qrCodeUrl: parcel.qrImage,
//       status: "awaiting_drop", // Corrected
//       lockerId: parcel.lockerId?.toString() || "",
//       metadata: {
//         description: parcel.description || "",
//       },
//       lockerLat: parcel.lockerLat,
//       lockerLng: parcel.lockerLng,
//     });
//   }

//   // ✅ Payment redirection
//   if (draft.paymentOption === "receiver_pays") {
//     const link = `${req.protocol}://${req.get("host")}/payment/receiver/${
//       parcel._id
//     }`;
//     return res.render("parcel/waiting-payment", { parcel });
//   }


//   res.redirect(`/parcel/${parcel._id}/success`);
// });
app.get("/payment/success", isAuthenticated, async (req, res) => {
  const { order_id, payment_id, signature } = req.query;

  // Verify signature
  const generatedSignature = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
    .update(order_id + "|" + payment_id)
    .digest("hex");

  if (generatedSignature !== signature) {
    req.flash("error", "Payment verification failed.");
    return res.redirect("/dashboard");
  }

  // Mark parcel as paid
  const parcel = await Parcel2.findOneAndUpdate(
    { razorpayOrderId: order_id },
    {
      paymentStatus: "completed",
      status: "awaiting_drop"
    },
    { new: true }
  );

  if (!parcel) {
    req.flash("error", "Parcel not found.");
    return res.redirect("/dashboard");
  }
await SessionIntent.findOneAndUpdate(
  { sessionId: req.sessionID, completed: false },
  { completed: true, endedAt: new Date() }
);
  await FunnelEvent.create({
    sessionId: req.sessionID,
    userId: req.user?._id || null,
    step: "send_parcel_submitted",
    timestamp: new Date()
  });
  res.redirect(`/parcel/${parcel._id}/success`);
});
// app.post("/payment/receiver/:id/success", isAuthenticated, async (req, res) => {
//   const parcel = await Parcel1.findById(req.params.id);
//   if (!parcel) return res.status(404).send("Parcel not found");

//   if (parcel.paymentStatus === "completed") {
//     return res.send("Payment already completed.");
//   }

//   parcel.status = "awaiting_drop";
//   parcel.paymentStatus = "completed";
//   parcel.droppedAt = new Date();
//   parcel.expiresAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000); // extend after payment

//   await parcel.save();
//   res.redirect(`/parcel/${parcel._id}/success`);
// });

app.get("/:id/qrpage",async(req,res)=>{
  const parcel = await Parcel2.findById(req.params.id);
   if (!parcel) return res.status(404).send("Parcel not found");
    res.render("parcel/success", { parcel });

})
app.get("/parcel/:id/success", async (req, res) => {
    const user = await User.findById(req.session.user._id);
  const parcel = await Parcel2.findById(req.params.id);
  if (!parcel) return res.status(404).send("Parcel not found");
     await client.messages.create({
  to: `whatsapp:+91${user.phone}`,
  from: 'whatsapp:+15558076515',
   messagingServiceSid: process.env.TWILIO_MESSAGING_SERVICE_SID_WHATSAPP,
  contentSid: 'HX8dc7a5b23a3a6a2a7ce8a4d2e577ac3c', 
  contentVariables: JSON.stringify({
  1: `${user.username}`, // Sender name
  2: `${req.params.id}/qrpage` // Parcel ID
})// Template SID
}).then(message => console.log('✅ WhatsApp Message Sent:', message.sid))
.catch(error => console.error('❌ WhatsApp Message Error:', error));
  parcel.location = {
    lat: 20.5937,
    lng: 78.9629,
  };

  res.render("parcel/success", { parcel });
});

function getEstimatedCost(size) {
  if (size === "small") return 10;
  if (size === "medium") return 20;
  return 30;
}

app.get("/parcel/:id/success", isAuthenticated, async (req, res) => {
  const parcel = await Parcel1.findById(req.params.id);
  if (!parcel) return res.status(404).send("Parcel not found");

  // Prepare location for sharing if needed
  parcel.location = {
    lat: 20.5937, // fallback India center or locker zone
    lng: 78.9629,
  };
  await notifyUserOnLockerBooking(
    parcel.receiverName,
    parcel.receiverPhone,
    parcel.accessCode,
    new Date().toLocaleString()
  );
  res.render("parcel/success", { parcel });
});
app.post("/api/locker/scan", async (req, res) => {
  const { accessCode } = req.body;

  if (!accessCode) {
    return res
      .status(400)
      .json({ success: false, message: "Access code is required." });
  }

  // Find the parcel by accessCode
  const parcel = await Parcel2.findOne({ accessCode });
  const parcelU = await incomingParcel.findOne({ accessCode });
  if (!parcel) {
    return res
      .status(404)
      .json({ success: false, message: "Parcel not found." });
  }

  if (parcel.status === "picked_up") {
    return res
      .status(400)
      .json({ success: false, message: "Parcel has already been picked up." });
  }

  if (parcel.status === "awaiting_drop") {
    // Get lockerId from request (where the user scanned)
    const { lockerId } = req.body;

    if (!lockerId) {
      return res.status(400).json({
        success: false,
        message: "Locker ID is required for drop-off.",
      });
    }

    // Find that specific locker
    const locker = await Locker.findOne({ lockerId });

    if (!locker) {
      return res.status(404).json({
        success: false,
        message: "Specified locker not found.",
      });
    }

    // Look for a free compartment in that locker
    const compartment = locker.compartments.find((c) => !c.isBooked);

    if (!compartment) {
      return res.status(503).json({
        success: false,
        message: "No available compartments in this locker.",
      });
    }

    // Lock the compartment
    compartment.isLocked = true;
    compartment.isBooked = true;
    compartment.currentParcelId = parcel._id;
    await locker.save();

    // Update parcel
    parcel.status = "awaiting_pick";
    parcel.lockerLat = locker.location.lat;
    parcel.lockerLng = locker.location.lng;
    parcel.lockerId = locker.lockerId;
    parcel.compartmentId = compartment.compartmentId;
    parcel.droppedAt = new Date();
    await parcel.save();

    // Update any secondary parcel collection if needed
    if (parcelU) {
      parcelU.lockerLat = locker.location.lat;
      parcelU.lockerLng = locker.location.lng;
      await parcelU.save();
    }

    io.emit("parcelUpdated", {
      parcelId: parcel._id,
      status: parcel.status,
      lockerId: parcel.lockerId,
      compartmentId: parcel.compartmentId,
      pickedUpAt: parcel.pickedUpAt,
      droppedAt: parcel.droppedAt,
    });

    

    return res.json({
      success: true,
      message: `Parcel dropped successfully. Compartment ${compartment.compartmentId} locked.`,
      compartmentId: compartment.compartmentId,
      lockerId: locker._id,
    });
  }

  if (parcel.status === "awaiting_pick" || parcel.status === "in_locker") {
    // This is a pickup

    const { lockerId } = req.body;

    if (!parcel.lockerId || !parcel.compartmentId) {
      return res.status(400).json({
        success: false,
        message: "Parcel is not assigned to any locker.",
      });
    }

    // Check that the scanned locker matches the parcel's locker
    if (lockerId !== parcel.lockerId) {
      return res.status(400).json({
        success: false,
        message: `This parcel belongs to locker ${parcel.lockerId}. Please scan it at the correct locker.`,
      });
    }

    // Find locker and compartment
    const locker = await Locker.findOne({ lockerId: parcel.lockerId });

    if (!locker) {
      return res
        .status(404)
        .json({ success: false, message: "Locker not found." });
    }

    const compartment = locker.compartments.find(
      (c) => c.compartmentId === parcel.compartmentId
    );
    if (!compartment) {
      return res
        .status(404)
        .json({ success: false, message: "Compartment not found." });
    }

    if (!compartment.isLocked) {
      return res
        .status(400)
        .json({ success: false, message: "Compartment is already unlocked." });
    }

    // Unlock compartment
    compartment.isLocked = false;
    compartment.isBooked = false;
    compartment.currentParcelId = null;
    await locker.save();

    // Update parcel
    parcel.status = "picked";
    parcel.pickedUpAt = new Date();
    await parcel.save();

    io.emit("parcelUpdated", {
      parcelId: parcel._id,
      status: parcel.status,
      lockerId: parcel.lockerId,
      compartmentId: parcel.compartmentId,
      pickedUpAt: parcel.pickedUpAt,
      droppedAt: parcel.droppedAt,
    });

    return res.json({
      success: true,
      message: `Parcel picked up successfully. Compartment ${compartment.compartmentId} unlocked.`,
      compartmentId: compartment.compartmentId,
      lockerId: locker._id,
    });
  }

  // If status is something else
  return res
    .status(400)
    .json({ success: false, message: `Parcel is in status: ${parcel.status}` });
});
app.get("/admin/analytics/funnel", async (req, res) => {
  const sessions = await SessionIntent.find().lean();

  const counts = {
    send: { total: 0, completed: 0 },
    receive: { total: 0, completed: 0 },
    explore: { total: 0, completed: 0 }
  };

  sessions.forEach(s => {
    counts[s.intent].total += 1;
    if (s.completed) counts[s.intent].completed += 1;
  });

  res.render("funnel", { counts });
});

/// unlock route

app.get("/drop/:accessCode", isAuthenticated, async (req, res) => {
  const parcel = await Parcel1.findOne({
    accessCode: req.params.accessCode,
    status: "awaiting_drop",
  });

  if (!parcel) return res.status(404).send("Invalid or expired QR");

  // Locker selection logic here
  const locker = await Locker1.findOne({
    size: parcel.size,
    isLocked: false,
    status: "available",
  });

  if (!locker) {
    return res.send("No compatible lockers available at this location.");
  }

  // Assign & lock
  parcel.lockerId = locker._id;
  parcel.status = "dropped";
  parcel.droppedAt = new Date();
  await parcel.save();

  locker.isLocked = true;
  locker.status = "occupied";
  await locker.save();

  res.send("✅ Locker opened! Place your parcel inside.");
});

app.get("/adminDash", (req, res) => {
  res.render("adminUpdated/dashboard");
});

app.get("/admnDash", isAdmin, async (req, res) => {
  const apiKeys = await ApiKey.find();
  const roles = await Role.find();
  const logs = await AuditLog.find().sort({ createdAt: -1 }).limit(20);

  res.render("admin/dashboard", { apiKeys, roles, logs });
});
const DUMMY_PLANS = [
  {
    id: "basic",
    name: "Basic Plan",
    price: 49,
    credits: 50,
    description:
      "Perfect for occasional users. Get 50 locker credits for light usage.",
  },
  {
    id: "pro",
    name: "Pro Plan",
    price: 99,
    credits: 150,
    description:
      "Great for regular users. Includes 150 credits at a discounted rate.",
  },
  {
    id: "elite",
    name: "Elite Plan",
    price: 449,
    credits: 500,
    description:
      "Best for businesses or heavy users. Unlock maximum value with 500 credits.",
  },
];

app.get("/plans", isAuthenticated, (req, res) => {
  res.render("subscription/plans", { plans: DUMMY_PLANS });
});

app.post("/subscribe/select", isAuthenticated, async (req, res) => {
  const selectedPlan = DUMMY_PLANS.find((p) => p.id === req.body.planId);
  if (!selectedPlan) return res.status(400).send("Invalid plan selected");

  const user = await User.findById(req.session.user._id);

  user.subscription = {
    planId: selectedPlan.id,
    status: "active",
    currentPeriodStart: new Date(),
    currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // +30 days
    cancelAtPeriodEnd: false,
    stripeSubscriptionId: null, // Dummy flow
  };

  // Optional: Give plan credits
  user.wallet.credits += selectedPlan.credits;

  await user.save();
  req.flash("success", "Subscription added Successfully!");
  res.redirect("/dashboard");
});

app.post("/subscribe/cancel", isAuthenticated, async (req, res) => {
  const user = await User.findById(req.session.user._id);

  if (!user.subscription?.planId) {
    return res.status(400).send("No active subscription.");
  }

  // Clear the subscription object completely
  user.subscription = {
    planId: null,
    status: "cancelled",
    currentPeriodStart: null,
    currentPeriodEnd: null,
    cancelAtPeriodEnd: false,
    stripeSubscriptionId: null,
  };

  await user.save();
  req.flash("success", "Your subscription has been cancelled.");
  res.redirect("/dashboard");
});

app.get("/newprofile", isAuthenticated, async (req, res) => {
  const user = await User.findById(req.session.user._id); // req.user is set via session/passport
  res.render("newprofile", { user, messages: req.flash() });
});

app.post("/newprofile", isAuthenticated, async (req, res) => {
  const { username, email } = req.body;

  try {
    await User.findByIdAndUpdate(req.user._id, {
      username,
      email,
    });

    req.flash("success", "Profile updated successfully!");
    res.redirect("/newprofile");
  } catch (err) {
    console.error(err);
    req.flash("error", "Something went wrong.");
    res.redirect("/newprofile");
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
      lockerBoxId: locker.lockerBoxId,
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

app.get("/history", isAuthenticated, async (req, res) => {
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
app.get(
  "/locker/directions/:lockerId/:compartmentId",
  isAuthenticated,
  async (req, res) => {
    const { lockerId, compartmentId } = req.params;
    const locker = await Locker.findOne({ lockerId });

    // For now just redirect to a dummy Google Maps link or custom UI
    res.redirect(
      `https://www.google.com/maps/dir/?api=1&destination=${locker.location.lat},${locker.location.lng}`
    );
  }
);
app.get("/profile", isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user;

    const user = await User.findById(req.session.user._id).populate("parcels");
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

app.get("/locker/:lockerId", isAuthenticated, async (req, res) => {
  const locker = await Locker.findOne({
    lockerId: req.params.lockerId,
  }).populate("compartments");
  if (!locker) return res.status(404).send("Locker not found");

  res.render("locker-details1", { locker, user: req.user });
});

app.post("/user/book", async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  const userId = req.session.user; // Adjust to your auth logic

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
      userId: req.session.user,
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
app.get("/courier/register", isAuthenticated, (req, res) => {
  res.render("courierRegister", { message: req.flash("error") });
});

// POST - Register New Courier
app.post("/courier/register", isAuthenticated, async (req, res) => {
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

app.get("/courier/login", isAuthenticated, (req, res) => {
  res.render("courierLogin", { message: req.flash("error") });
});

app.post("/courier/login", isAuthenticated, async (req, res) => {
  const { phone, otp } = req.body;
  const courier = await Courier.findOne({ phone });

  if (!courier || courier.otp !== otp) {
    req.flash("error", "Invalid phone or OTP");
    return res.redirect("/courier/login");
  }

  req.session.courierId = courier._id;
  res.redirect("/courier/dashboard");
});

app.get("/courier/dashboard", isAuthenticated, async (req, res) => {
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

app.post("/courier/deliver", isAuthenticated, async (req, res) => {
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

app.get("/locker/emulator/:lockerId", isAuthenticated, async (req, res) => {
  try {
    const locker = await Locker.findOne({ lockerId: req.params.lockerId });

    if (!locker) {
      // Render a "not found" page
      return res.render("lockerNotFound.ejs", {
        lockerId: req.params.lockerId,
      });
    }
    const compartments = locker.compartments;
    const { lockerId } = req.params;
    res.render("newlocker.ejs", { lockerId, compartments });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err });
  }
});
app.get("/incomingdetails/:id", isAuthenticated, async (req, res) => {
  const { id } = req.params;
  try {
    const parcel = await Parcel2.findById(id);
    const username = parcel.senderName;
    const user = await User.findOne({username : username});
    if (!parcel) {
      return res.status(404).render("errorpage", {
        errorMessage: "Parcel not found.",
      });
    }

    res.render("incomingDetails", { parcel, user });
  } catch (err) {
    console.error("Error fetching parcel details:", err);
    res.status(500).render("errorpage", {
      errorMessage: "Server error fetching parcel details.",
    });
  }
});
app.get("/virtuallocker", (req, res) => {
  res.render("lockerEmu");
});
function getDistanceFromLatLonInM(lat1, lon1, lat2, lon2) {
  function deg2rad(deg) {
    return deg * (Math.PI / 180);
  }
  const R = 6371e3; // Earth's radius in meters
  const dLat = deg2rad(lat2 - lat1);
  const dLon = deg2rad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(deg2rad(lat1)) *
      Math.cos(deg2rad(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

app.post("/api/nearest-locker", async (req, res) => {
  try {
    const { latitude, longitude } = req.body;
    if (!latitude || !longitude) {
      return res
        .status(400)
        .json({ success: false, message: "Missing coordinates" });
    }

    // Fetch all lockers
    const lockers = await Locker.find({});

    if (!lockers.length) {
      return res
        .status(404)
        .json({ success: false, message: "No lockers available" });
    }

    // Find the nearest locker
    let nearestLocker = null;
    let minDistance = Infinity;

    lockers.forEach((locker) => {
      if (
        !locker.location ||
        locker.location.lat == null ||
        locker.location.lng == null
      )
        return;

      const dist = getDistanceFromLatLonInM(
        latitude,
        longitude,
        locker.location.lat,
        locker.location.lng
      );

      if (dist < minDistance) {
        minDistance = dist;
        nearestLocker = locker;
      }
    });

    if (!nearestLocker) {
      return res
        .status(404)
        .json({
          success: false,
          message: "No lockers with valid location data",
        });
    }

    return res.json({
      success: true,
      locker: {
        lockerId: nearestLocker.lockerId,
        address: nearestLocker.location.address,
        coordinates: {
          lat: nearestLocker.location.lat,
          lng: nearestLocker.location.lng,
        },
        totalCompartments: nearestLocker.compartments.length,
        availableCompartments: nearestLocker.compartments.filter(
          (c) => !c.isBooked
        ).length,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
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
  const user = await User.findById(req.session.user._id);
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

app.get("/admin/analytics",isAdmin, async(req,res)=>{

})
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

server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});