const express = require("express");
const mongoose = require("mongoose");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const cors = require("cors");
const fs = require("fs");
const LRU = require("lru-cache");
const Razorpay = require("razorpay");
const Version = require("./models/Version.js");
const methodOverride = require('method-override');
const cookieParser = require('cookie-parser');
const axios = require("axios");
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
const Contact = require("./models/contacts.js");
const SavedAddress = require("./models/savedAddress.js");
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
app.set('trust proxy', 1);
app.use(cookieParser(process.env.COOKIE_SECRET)); // <- add a strong secret
app.engine("ejs", ejsMate); // Set ejs-mate as the EJS engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(methodOverride('_method'));
app.use(express.static("public"));

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret", // Use env var in production
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: MONGO_URI,
      ttl: 60 * 60 * 24 * 7, // 7 days in seconds
    }),
    cookie: {
    secure: false,     // Must be false if not using HTTPS locally
    httpOnly: true,
    sameSite: "lax",       // Prevents cross-site issues
   maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      
    },
      rolling: true, 
  })
);



const LOGIN_COOKIE = 'login_phone';

function setLoginPhoneCookie(res, phone) {
  res.cookie(LOGIN_COOKIE, phone, {
    signed: true,
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production', // only over HTTPS in prod
    maxAge: 5 * 60 * 1000, // 5 minutes
    path: '/',            // available across your app
  });
}

function clearLoginPhoneCookie(res) {
  res.clearCookie(LOGIN_COOKIE, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  });
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
  if (req.session.user) {
    req.user = req.session.user;
    res.locals.user = req.session.user;
  } else {
    res.locals.user = null;
  }
  next();
});

app.use(passport.initialize());
app.use(passport.session());




// passport.use(
//   new GoogleStrategy(
//     {
//       clientID: "587834679125-34p3obvnjoa9o8qsa4asgrgubneh5atg.apps.googleusercontent.com",
//       clientSecret: "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",
//       callbackURL: process.env.GOOGLE_CALLBACK_URL,
//       passReqToCallback: true, // Needed to access `req` in verify function
//     },
//     async (req, accessToken, refreshToken, profile, done) => {
//       try {
//         // If user is already logged in, link their account
//         if (req.user) {
//           const currentUser = await User.findById(req.user._id);
//           if (!currentUser) return done(null, false);

//           currentUser.googleId = profile.id;
//           currentUser.email = currentUser.email || profile.emails?.[0]?.value;
//           await currentUser.save();

//           return done(null, currentUser);
//         }

//         // Otherwise: normal login or signup
//         let user = await User.findOne({ googleId: profile.id });

//         if (!user) {
//           user = new User({
//             username: profile.displayName,
//             googleId: profile.id,
//             email: profile.emails?.[0]?.value,
//           });
//           await user.save();
//         }

//         return done(null, user);
//       } catch (err) {
//         return done(err);
//       }
//     }
//   )
// );













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




passport.serializeUser((user, done) => {
  done(null, user._id); // Safer and clearer
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    if (!user) {
      // Instead of throwing error, return false
      return done(null, false); // ✅ this means: "no user found, unauthenticated"
    }
    return done(null, user);
  } catch (err) {
    console.error("Deserialize error:", err);
    return done(err, null); // ⛔ Passport will treat this as a hard error
  }
});







const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || "your_key_id",
  key_secret: process.env.RAZORPAY_KEY_SECRET || "your_key_secret",
});

function isAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated() && req.user) {
    return next();
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


app.get("/", (req, res) => {
  res.redirect("/mobileDashboard");
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

app.get("/users", async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 }).lean();

    res.render("users", {
      users,
      activePage: "users"
    });
  } catch (err) {
    console.error("Failed to load users:", err);
    res.status(500).send("Error loading users");
  }
});
app.post("/admin/users/:id/delete", async (req, res) => {
  

  try {
    await User.findByIdAndDelete(req.params.id);
    res.redirect("/users");
  } catch (err) {
    console.error("Delete failed:", err);
    res.status(500).send("Failed to delete user");
  }
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
  
  // const cachedHtml = locationsCache.get(cacheKey);
  // if (cachedHtml) {
  //   console.log("✅ Served /locations from cache");
  //   return res.send(cachedHtml);
  // }

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
        // locationsCache.set(cacheKey, html);
        // console.log("✅ Cached /locations HTML");

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
  
 

  try {
    const user = await User.findById(req.session.user._id).lean();

    res.render("account", { user, activePage: "account" }, (err, html) => {
      if (err) {
        console.error("Error rendering /account:", err);
        return res.status(500).send("Internal Server Error");
      }

      

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
  const parcelLocker = parcel.lockerId || "";
  const accessCode = parcel.accessCode;
  let qrImage;
    if (parcelLocker != "") {
      qrImage = await QRCode.toDataURL(JSON.stringify({ accessCode, parcelLocker }));
    } else {
      qrImage = await QRCode.toDataURL(JSON.stringify({ accessCode }));
    }
  if (!parcel) return res.status(404).send("Parcel not found");
  if (!parcel.qrImage)
    return res.status(400).send("No QR code saved for this parcel");
  res.render("qrPage", { parcel,qrImage });
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
     if (req.session.inProgressParcelId) {
    await Parcel2.findByIdAndDelete(req.session.inProgressParcelId);
    delete req.session.inProgressParcelId;
  }
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




app.post("/log-version", async (req, res) => {
  const { version, pushedBy = "auto" } = req.body;

  if (!version) {
    return res.status(400).json({ error: "version is required" });
  }

  try {
    // Optional: get commit hash
    const commitHash = require("child_process")
      .execSync("git rev-parse HEAD")
      .toString()
      .trim();

    // Optional: mark previous as inactive
    await Version.updateMany({}, { isCurrent: false });

    const zipPath = path.join("backups", `release_${version}.zip`);

    const entry = await Version.create({
      version,
      commitHash,
      zipPath,
      pushedAt: new Date(),
      isCurrent: true,
      deployedBy: pushedBy
    });

    res.status(201).json({ message: "Version logged", data: entry });
  } catch (err) {
    console.error("Logging error:", err);
    res.status(500).json({ error: "DB error", details: err.message });
  }
});

//VERSION TRACKING

app.get("/version", (req, res) => {
  const versionPath = path.join(__dirname, "version.json");
  try {
    const versionData = fs.readFileSync(versionPath, "utf8");
    res.json(JSON.parse(versionData));
  } catch (error) {
    res.status(500).json({ error: "Version not found" });
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

// ------------------------------------------GOOGLE LOGIN ROUTES---------------------------------------------------

app.get("/link-phone", (req, res) => {
  res.render("link-phone", { error: null});
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
  const existing = await User.findOne({ phone: phone });
  if (existing && String(existing._id) !== String(req.session.user._id)) {
     req.session.mergePhone = canonicalPhone;
    req.session.mergeTargetUserId = existing._id;
     return res.render("merge-confirm", {
      phone: canonicalPhone,
      existingUser: existing,
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



app.post("/merge-request", async (req, res) => {
  const phone = req.session.mergePhone;
  if (!phone) return res.redirect("/link-phone");

  try {
    await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({ to: phone, channel: "sms" });

    res.render("verify-merge-phone", { phone });
  } catch (err) {
    console.error("Merge OTP error:", err);
    res.render("merge-confirm", {
      phone,
      error: "❌ Could not send OTP. Try again.",
    });
  }
});



app.post("/verify-merge-phone", async (req, res) => {
  const code = req.body.code;
  const phone = req.session.mergePhone;
  const targetId = req.session.mergeTargetUserId;
  const currentUser = req.session.user;

  if (!code || !phone || !targetId || !currentUser) {
    return res.redirect("/link-phone");
  }

  try {
    const result = await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({ to: phone, code });

    if (result.status !== "approved") {
      return res.render("verify-merge-phone", {
        phone,
        error: "❌ Invalid OTP. Try again.",
      });
    }

    // 🔁 Do actual merge
    await mergeAccounts(currentUser._id, targetId);

    // Optional: clear session + login as target account
    req.session.user = await User.findById(targetId);
    req.session.mergePhone = null;
    req.session.mergeTargetUserId = null;

    res.redirect("/mobileDashboard");
  } catch (err) {
    console.error("OTP verify error:", err);
    res.render("verify-merge-phone", {
      phone,
      error: "❌ Verification failed. Try again.",
    });
  }
});




async function mergeAccounts(fromUserId, toUserId) {
  const fromUser = await User.findById(fromUserId);
  const toUser = await User.findById(toUserId);

  if (!fromUser || !toUser) {
    throw new Error("One of the users was not found during merge.");
  }
  
  // Transfer the phone number from the existing account to the current one
   fromUser.phone =toUser.phone;
  console.log(fromUser.phone);
  // Save the updated current user
  await toUser.save();

  // Delete the old (from) user
  await User.deleteOne({ _id: fromUserId });
}






// app.get("/verify-link-phone", (req, res) => {
//   res.render("verify-link-phone", { error: null });
// });

// app.post("/verify-link-phone", async (req, res) => {
//   const { otp } = req.body;
//   const phone = req.session.linkPhone;
//   const canonicalPhone = `+91` + phone;
//   try {
//     const verificationCheck = await client.verify.v2
//       .services(process.env.TWILIO_VERIFY_SERVICE_SID)
//       .verificationChecks.create({
//         to: canonicalPhone,
//         code: otp,
//       });

//     if (verificationCheck.status !== "approved") {
//       return res.render("verify-link-phone", { error: "❌ Invalid OTP." });
//     }

//     const user = await User.findById(req.session.user._id);
//     user.phone = phone;
//     user.isPhoneVerified = true;
//     await user.save();

//     // Update session
//     req.session.phone = phone;
//     req.session.user.phone = phone;
//     delete req.session.linkPhone;
//     accountCache.delete("account:" + req.session.user._id);
//     req.flash("success", "✅ Phone linked successfully.");
//     const redirectTo = req.session.pendingRedirectAfterPhoneLink || "/dashboard";
// delete req.session.pendingRedirectAfterPhoneLink;
// res.redirect(redirectTo);
//     // res.redirect("/send/step2");
//   } catch (err) {
//     console.error("Error linking phone:", err);
//     res.render("verify-link-phone", {
//       error: "❌ Failed to verify. Try again.",
//     });
//   }
// });

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

require("dotenv").config();
const twilio = require("twilio");
const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

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
      senderId: req.user._id
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



// app.post("/otpLogin", async (req, res) => {
  
//   // await trackFunnelStep(req, "login_phone", { phone: req.body.phone });
//   const { phone } = req.body;

//   // Check if user exists
//   const user = await User.findOne({ phone });

//   req.session.phone = phone;

//   // Send OTP using Twilio Verify
//   try {
//     await client.verify.v2
//       .services(process.env.TWILIO_VERIFY_SERVICE_SID)
//       .verifications.create({
//         to: `+91${phone}`,
//         channel: "sms",
//       });

//     // If user exists, go to OTP verify page
//     // If user doesn't exist, also go to OTP verify (we'll handle the check after OTP)
//     res.redirect("/verify-login");
//   } catch (err) {
//     console.error("OTP send error:", err.message);
//     res.render("login", { error: "❌ Failed to send OTP. Try again." });
//   }
// });



// app.post("/otpLogin", async (req, res) => {
//   const { phone } = req.body;
//   req.session.phone = phone;

//   await trackFunnelStep(req, "login_phone", { phone });

//   // Check if ENV variables are loaded
//   console.log("Verify SID:", process.env.TWILIO_VERIFY_SERVICE_SID);

//   try {
//     await client.verify.v2
//       .services(process.env.TWILIO_VERIFY_SERVICE_SID)
//       .verifications.create({
//         to: `+91${phone}`,
//         channel: "sms",
//       });

//     res.redirect("/verify-login");
//   } catch (err) {
//     console.error("OTP send error:", err); // full object
//     res.render("login", { error: "❌ Failed to send OTP. Try again." });
//   }
// });




// app.post("/verify-login", async (req, res) => {
//   await trackFunnelStep(req, "otp_entered");
  


//   const { otp } = req.body;
//   const phone = req.session.phone;

//   try {
//     const verificationCheck = await client.verify.v2
//       .services(process.env.TWILIO_VERIFY_SERVICE_SID)
//       .verificationChecks.create({
//         to: `+91${phone}`,
//         code: otp,
//       });

//     if (verificationCheck.status !== "approved") {
//       return res.render("verify-login", {
//         error: "❌ Invalid OTP. Try again.",
//       });
//     }

//     let user = await User.findOne({ phone });
// if (!user) {
//   return res.redirect("/set-username", 
    
   
//   );
// }

// if (user) {
//   user.lastLogin = new Date();
//   await user.save();
// }

 

//     // ✅ Existing user
//     req.session.user = {
//       _id: user._id,
//       uid: user.uid,
//       username: user.username || null,
//       phone: user.phone || null,
//       email: user.email || null,
//       wallet: user.wallet || { credits: 0 },
//     };

//     delete req.session.phone;
//     res.redirect("/mobileDashboard");
//   } catch (err) {
//     console.error("OTP Verify Error:", err.message);
//     res.render("verify-login", { error: "❌ OTP verification failed." });
//   }
// });

// app.get("/set-username", (req, res) => {
//   if (!req.session.phone) return res.redirect("/login");
//   res.render("set-username", { error: null });
// });

// app.post("/set-username", async (req, res) => {
//   const { username } = req.body;
//   const phone = req.session.phone;

//   try {
//     const existingUsername = await User.findOne({ username });
//     if (existingUsername) {
//       return res.render("set-username", {
//         error: "❌ Username already taken.",
//       });
//     }

//     const user = new User({
//       phone,
//       username,
//       isPhoneVerified: true,
//     });

//     await user.save();

//     req.session.user = {
//       _id: user._id,
//       uid: user.uid,
//       username: user.username || null,
//       phone: user.phone || null,
//       email: user.email || null,
//       wallet: user.wallet || { credits: 0 },
//     };

    
//     res.redirect("/mobileDashboard");
//   } catch (err) {
//     res.render("set-username", {
//       error: "❌ Failed to save user.",
//     });
//   }
// });
// app.post("/resend-login-otp", async (req, res) => {
//   const phone = req.session.phone;

//   if (!phone) {
//     return res.render("login", {
//       error: "Session expired. Please login again.",
//     });
//   }

//   try {
//     await client.verify.v2
//       .services(process.env.TWILIO_VERIFY_SERVICE_SID)
//       .verifications.create({ to: `+91${phone}`, channel: "sms" });

//     console.log(`OTP resent to ${phone}`);
//     res.redirect("/verify-login");  // session carries the phone
//   } catch (err) {
//     console.error("Error resending OTP:", err.message);
//     res.render("verify-login", {
//       error: "❌ Failed to resend OTP. Please try again.",
//       phone,
//     });
//   }
// });

// ======================================================= MOBILE LIKE DESIGB==========================================================


app.get('/auth/google', (req, res, next) => {
  const isLinking = req.query.link === 'true';
  const authenticator = passport.authenticate('google', {
    scope: ['profile', 'email'],
    state: isLinking ? 'link' : 'login',
  });
  authenticator(req, res, next);
});



//// GOOGLE LOGIN UPDATED NEW ROUTES

// app.get('/auth/google',
//   passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  async (req, res) => {
    try {
      // Make sure req.user exists (should be guaranteed by passport if successful)
      if (!req.user) {
        return res.redirect("/login");
      }

      // Save user info to session
      req.session.user = {
        _id: req.user._id,
        uid: req.user.uid,
        username: req.user.username,
        phone: req.user.phone || null,
        email: req.user.email,
        wallet: req.user.wallet || { credits: 0 },
      };

      // Find or create the user in your DB (if needed)
      let user = await User.findOne({ username: req.user.username });

      if (!user) {
        // Be sure `google Id`, `email`, `username` are defined
        const { googleId, email, username } = req.user;

        user = await User.create({
          googleId,
          email,
          username,
          phone: req.user.phone || null,
        });
      }

      // Update last login timestamp
      user.lastLogin = new Date();
      await user.save();

      // Optional analytics step
      await trackFunnelStep(req, "login_oauth", { phone: req.user.phone || null });

      // Redirect to saved URL or default
      const redirectTo = req.session.redirectTo || "/mobileDashboard";
      delete req.session.redirectTo;

      return res.redirect(redirectTo);
    } catch (err) {
      console.error("OAuth callback error:", err);
      return res.redirect("/login");
    }
  }
);


app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});


// -------------------------------------------------------------------------------------------------------------------------------------------------------

/// OTP LOGIN ROUTES 
 const VERIFY_SID = process.env.TWILIO_VERIFY_SERVICE_SID;
app.post("/otpLogin", async (req, res) => {
  const { phone } = req.body;
  // Basic phone number validation
  if (!phone || !/^\d{10}$/.test(phone)) {
    return res.render("login", { error: "⚠️ Please enter a valid 10-digit phone number." });
  }

  // Save phone to session
    setLoginPhoneCookie(res, phone);
  
  // Optional: Analytics/tracking
  await trackFunnelStep(req, "login_phone", { phone });

  // Debug log (ensure .env has this variable)
  console.log("Verify SID:", VERIFY_SID);

  try {
    await client.verify.v2
      .services(VERIFY_SID)
      .verifications.create({
        to: `+91${phone}`,
        channel: "sms",
      });
    req.session.save((err) => {
  if (err) {
    console.error('Session save error before redirect:', err);
    return res.render('login', { error: '⚠️ Session error. Please try again.' });
  }
  return res.redirect('/verify-login');
});
  } catch (err) {
    console.error("OTP send error:", err?.message || err);

    return res.render("login", {
      error: "❌ Failed to send OTP. Please try again later.",
    });
  }
});

app.get("/verify-login", (req, res) => {
  const phone = req.session.phone; // saved from login step
  res.render("verify-login", { error: null, phone });
});



app.post("/verify-login", async (req, res) => {
  await trackFunnelStep(req, "otp_entered");
 
  const { otp } = req.body;
  console.log(otp);
   const phone = req.signedCookies?.login_phone || "";
  console.log(phone);

  if (!otp) {
    return res.render("verify-login", {
      error: "⚠️ Please enter a valid OTP.",
    });
  }

  try {
    const verificationCheck = await client.verify.v2
      .services(VERIFY_SID)
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
      req.session.user = { phone };

      return req.session.save((err) => {
        if (err) {
          console.error("Session save error:", err);
          return res.render("verify-login", {
            error: "⚠️ Session error. Please try again.",
          });
        }
        return res.redirect("/set-username");
      });
    }

    // Safe to proceed now
    user.lastLogin = new Date();
    await user.save();

    req.session.user = {
      _id: user._id,
      uid: user.uid,
      username: user.username || null,
      phone: user.phone || null,
      email: user.email || null,
      wallet: user.wallet || { credits: 0 },
    };

    return res.redirect("/mobileDashboard");

  } catch (err) {
    console.error("OTP Verify Error:", err?.message || err);
    return res.render("verify-login", {
      error: "❌ OTP verification failed. Please try again.",
    });
  }
});




app.get("/set-username", (req, res) => {
  const phone = req.signedCookies?.[LOGIN_COOKIE];
  if (!/^\d{10}$/.test(phone || "")) {
  return res.redirect("/login");
}
  res.render("set-username", { error: null });
});



app.post("/set-username", async (req, res) => {
  const { username } = req.body;
  const phone = req.signedCookies?.[LOGIN_COOKIE];
  console.log(phone);

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

    
    res.redirect("/mobileDashboard");
  } catch (err) {
    res.render("set-username", {
      error: err.message,
    });
  }
});



app.post("/resend-login-otp", async (req, res) => {
  const phone = req.session.phone;

  // Ensure session has phone number
  if (!phone) {
    return res.render("login", {
      error: "⚠️ Session expired. Please enter your phone number again.",
    });
  }

  try {
    // Resend OTP using Twilio
    await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({
        to: `+91${phone}`,
        channel: "sms",
      });

    console.log(`✅ OTP resent to ${phone}`);
    return res.redirect("/verify-login");
  } catch (err) {
    console.error("❌ Error resending OTP:", err?.message || err);
    return res.render("verify-login", {
      error: err,
      phone,
    });
  }
});

// ---------------------------------------------------------------------------------------------------------------------------------------------------


//// LINK PHONE AFTER GOOGLE ACCOUNT



app.get("/mobile/link-phone", (req, res) => {
  res.render("link-phone", { error: null});
});



app.post("/mobile/link-phone", async (req, res) => {
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
  const existing = await User.findOne({ phone: phone });
  if (existing && String(existing._id) !== String(req.session.user._id)) {
     req.session.mergePhone = canonicalPhone;
    req.session.mergeTargetUserId = existing._id;
     return res.render("merge-confirm", {
      phone: canonicalPhone,
      existingUser: existing,
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
    res.render("link-phone", { error: err});
  }
});

app.post("/mobile/merge-confirm", async (req, res) => {
  const phone = req.session.mergePhone;
  if (!phone || !req.session.mergeTargetUserId) {
    return res.redirect("/mobile/link-phone");
  }

  try {
    await client.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID).verifications.create({
      to: phone,
      channel: "sms",
    });

    req.session.linkPhone = phone.slice(3); // remove +91
    req.session.isMergeFlow = true;
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
  const otp = req.body.otp;
  const phone = req.session.linkPhone;
  const canonicalPhone = "+91" + phone;

  try {
    const verificationCheck = await client.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({
        to: canonicalPhone,
        code: otp,
      });

    if (verificationCheck.status !== "approved") {
      return res.render("verify-link-phone", {
        phone: canonicalPhone,
        error: "❌ Invalid OTP. Try again.",
      });
    }

    const user = await User.findById(req.session.user._id);

    // Merge flow
    if (req.session.isMergeFlow && req.session.mergeTargetUserId) {
      const oldUser = await User.findById(req.session.mergeTargetUserId);

      if (oldUser) {
        // Optional: merge other fields like orders, history, etc. here

        oldUser.phone = undefined;
        oldUser.status = "merged";
        await oldUser.save();
        user.isPhoneVerified = true;
        user.phone = phone;
        await user.save();
      }
    } else {
      user.phone = phone;
      user.isPhoneVerified = true;
      await user.save();
    }

    // Cleanup
    req.session.linkPhone = null;
    req.session.mergePhone = null;
    req.session.mergeTargetUserId = null;
    req.session.isMergeFlow = null;
    const redirectTo = req.session.pendingRedirectAfterPhoneLink || "/mobile/sendParcel";
    res.redirect(redirectTo);
  } catch (err) {
    console.error("OTP verification failed:", err);
    res.render("verify-link-phone", {
      phone: canonicalPhone,
      error: err,
    });
  }
});








app.get("/mobileDashboard", isAuthenticated, async (req, res) => {

  const user = await User.findById(req.session.user._id).lean();
  if (!user) return res.redirect("/login");

  try {
    // Sent by user, excluding self-storage
    const sentParcels = await Parcel2.find({
      senderPhone : user.phone,
      store_self: { $ne: true }
    })
      .sort({ createdAt: -1 })
      .lean();

    // Received by user, excluding self-storage
    const receivedParcels = await Parcel2.find({
      receiverPhone: user.phone,
      store_self: { $ne: true }
    })
      .sort({ createdAt: -1 })
      .lean();

    // Optional: Self-stored parcels
    const storedParcels = await Parcel2.find({
      senderPhone : user.phone,
      store_self: true
    })
      .sort({ createdAt: -1 })
      .lean();

    // Awaiting pickup counter
    const awaitingPickCount = await Parcel2.countDocuments({
      status: "awaiting_pick",
      receiverPhone: user.phone
    });

    res.render("mobile/dashboard", {
      user,
      sentParcels,
      receivedParcels,
      storedParcels,
      awaitingPickCount
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("Server error loading parcels.");
  }
});


app.delete('/mobile/parcel/del/:id', async (req, res) => {
  try {
    await Parcel2.findByIdAndDelete(req.params.id);
    res.redirect('/mobileDashboard'); // or wherever you want to go after deletion
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});
app.get("/mobile/parcel/:id", isAuthenticated,async (req, res) => {
  const parcel = await Parcel2.findById(req.params.id);
   const now = new Date();
  const isExpired = now > parcel.expiresAt;

  res.render("mobile/parcel-tracking", { parcel, isExpired });
});



app.get("/mobile/sendParcel", isAuthenticated, async(req,res)=>{
   const user = await User.findById(req.session.user._id).lean();
    
  if (!user) return res.redirect("/login");
   const lockers = await Locker.find();
    
    res.render("mobile/sendParcel",{user,lockers});
})

app.get("/mobile/receive", isAuthenticated, async(req,res)=>{
     const user = await User.findById(req.session.user._id).lean();
  if (!user) return res.redirect("/login");
    try {
    const userPhone = req.session.user.phone;

    const incomingParcels = await Parcel2.find({
      receiverPhone: userPhone
    }).sort({ createdAt: -1 });

    const filteredParcels = incomingParcels.filter(
      p => p.status === "awaiting_pick"
    );

    res.render("mobile/receive", {
      parcels: filteredParcels,
      parcelCount: filteredParcels.length
    });
  } catch (error) {
    console.error("Error fetching parcels:", error);
    res.status(500).send("Server Error");
  }
});

app.get("/mobileAccount",isAuthenticated,async(req,res)=>{
     try {
    const user = await User.findById(req.session.user._id).lean();
       if (!user) return res.redirect("/login");
    res.render("mobile/account", { user}, (err, html) => {
      if (err) {
        console.error("Error rendering /account:", err);
        return res.status(500).send("Internal Server Error");
      }

      

      res.send(html);
    });
  } catch (err) {
    console.error("Error loading /account:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/mobile/store",isAuthenticated,async(req,res)=>{
     try {
       const user = await User.findById(req.session.user._id).lean();
  if (!user) return res.redirect("/login");
    const lockersRaw = await Locker.find({}).lean();
    const lockers = lockersRaw.map((locker) => ({
      lockerId: locker.lockerId,
      compartments: locker.compartments,
      location: locker.location || { lat: null, lng: null, address: "" },
    }));
    res.render(
      "mobile/store",
      {
        lockers,
      },
      (err, html) => {
        if (err) {
          console.error("Error rendering locations:", err);
          return res.status(500).send("Internal Server Error");
        }
        res.send(html);
      }
    );
  } catch (err) {
    console.error("Error loading locations:", err);
    res.status(500).send("Internal Server Error");
  }
});


app.get("/mobile/send/step2", isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user._id);
    if (!user) return res.redirect("/login");

    const size = req.query.size;
    const isSelf = req.query.self === 'true';

    const savedContacts = await Contact.find({ userId: user._id }).sort({ createdAt: -1 });
    const savedAddresses = await SavedAddress.find({ userId: user._id });

    if (!req.session.parcelDraft) req.session.parcelDraft = {};

    // Redirect if no phone is linked
    if (!user.phone) {
       req.session.pendingRedirectAfterPhoneLink = `/mobile/send/step2${size ? `?size=${size}` : ""}`;
      req.flash("error", "Please verify your phone number to continue.");
      return res.redirect("/mobile/link-phone");
    }

    // If a size is passed, update parcelDraft
    if (size) {
      req.session.parcelDraft.size = size;
      req.session.parcelDraft.type = "package";
      req.session.parcelDraft.description = "";
    }

    // If user is sending to self, auto-fill receiver info
    if (isSelf) {
      req.session.parcelDraft.receiverName = user.username || "Self";
      req.session.parcelDraft.receiverPhone = user.phone;
      req.session.parcelDraft.isSelf = true;
      console.log("Self-send to:", user.phone);
      return res.redirect("/mobile/send/step3");  // ✅ FIXED missing slash
    }

    const lockers = await Locker.find({
      "compartments.isBooked": false
    });

    res.render("mobile/parcel/step2", {
      lockers,
      savedAddresses,
      savedContacts
    });

  } catch (err) {
    console.error("Error in /mobile/send/step2:", err);
    res.status(500).send("Server error. Please try again.");
  }
});

app.post("/mobile/send/step2", isAuthenticated, async (req, res) => {
  
  
    const {
    receiverName,
    receiverPhone,
    deliveryOption,
    receiverDeliveryMethod,
    recipientAddress,
    recipientPincode,
    selectedLocker,
    saveContact,
    
  } = req.body;

  /// SAVE CONTACT FLOW
  if (saveContact === 'true' && receiverName && receiverPhone) {
    try {
      const existingContact = await Contact.findOne({
        userId: req.user._id,
        phone: receiverPhone.trim(),
      });
      if (!existingContact) {
        const newContact = new Contact({
        userId: req.user._id,
        name: receiverName.trim(),
        phone: receiverPhone.trim(),
      });
      await newContact.save();
      } else {
        console.log("Contact already exists. Skipping save.");
      }
    } 
    catch (err) {
      console.error("Error saving contact:", err);
    }}
  const user = await User.findById(req.session.user._id);
  if (!req.session.parcelDraft) req.session.parcelDraft = {};
  
  // STORE FOR SELF
  if (deliveryOption === "self") {
    req.session.parcelDraft.isSelf = true;
    req.session.parcelDraft.receiverName = user.username || "Self";
    req.session.parcelDraft.receiverPhone = user.phone || "";
    req.session.parcelDraft.receiverDeliveryMethod = "self_pickup";
  }

  else {
    if (!receiverName || !receiverPhone) {
      req.flash("error", "Please enter both name and phone for the recipient.");
      return res.redirect("/mobile/send/step2");
    }
     if (!receiverDeliveryMethod) {
      req.flash("error", "Please select how the receiver will receive the parcel.");
      return res.redirect("/mobile/send/step2");
    }

    req.session.parcelDraft.isSelf = false;
    req.session.parcelDraft.receiverName = receiverName;
    req.session.parcelDraft.receiverPhone = receiverPhone;
    req.session.parcelDraft.receiverDeliveryMethod = receiverDeliveryMethod;
    

    if (receiverDeliveryMethod === "address_delivery") {
      if (!recipientAddress || !recipientPincode || !selectedLocker) {
        req.flash("error", "Please fill in recipient address, pincode, and select a dispatch locker.");
        return res.redirect("/mobile/send/step2");
      }
      if (!selectedLocker || !mongoose.Types.ObjectId.isValid(selectedLocker)) {
        req.flash("error", "Please select a valid locker for dispatch.");
        return res.redirect("/mobile/send/step2");
      }

      const locker = await Locker.findById(selectedLocker);
      const lockerPincode = locker?.location?.pincode || "";

      // storing address and locker info

      req.session.parcelDraft.recipientAddress = recipientAddress;
      req.session.parcelDraft.recipientPincode = recipientPincode;
      req.session.parcelDraft.selectedLocker = selectedLocker;
      req.session.parcelDraft.selectedLockerPincode =lockerPincode;
      req.session.parcelDraft.status = "awaiting_drop";
      if (receiverDeliveryMethod === "address_delivery") {
        /// SAVE ADDRESS TO DB
        if (
        req.body.saveAddress === "true" &&
        req.body.recipientAddress &&
        req.body.recipientPincode &&
        req.body.receiverName
        ){
          const alreadyExists = await SavedAddress.findOne({
          userId: req.user._id,
          address: req.body.recipientAddress.trim(),
          pincode: req.body.recipientPincode.trim()
        });
        if (!alreadyExists) {
          await SavedAddress.create({
            userId: req.user._id,
            address: req.body.recipientAddress.trim(),
            pincode: req.body.recipientPincode.trim(),
            ownerName : req.body.receiverName,
            label: "Saved on " + new Date().toLocaleDateString()
          });
        }
      }
    }
  }
}
  if (receiverDeliveryMethod === "address_delivery") {
    return res.redirect("/mobile/send/estimate");
  }
  else{
    return res.redirect("/mobile/send/step3");
  }
});



app.get("/mobile/send/step3", isAuthenticated, async (req, res) => {
   const user = await User.findById(req.session.user._id).lean();
  if (!user) return res.redirect("/login");
  try {
    if (!req.session.parcelDraft) {
  req.flash("error", "Parcel draft not found. Please start again.");
  return res.redirect("/mobile/sendParcel");
}

    const { rate } = req.query;
    const draft = req.session.parcelDraft;
    const lockerId = draft.selectedLocker;
    const prestatus = draft.status;
    const user = await User.findById(req.session.user._id);
    const accessCode = Math.floor(100000 + Math.random() * 900000).toString();

    let cost = getEstimatedCost(draft.size);
    if (draft.receiverDeliveryMethod === "address_delivery") {
      cost += parseFloat(rate);
    }

    let qrImage;
    console.log(lockerId);
    if (lockerId) {
      qrImage = await QRCode.toDataURL(accessCode);
    } else {
      qrImage = await QRCode.toDataURL(accessCode);
    }

    // Check store_self logic
    if (draft.isSelf) {
      if (!draft.receiverPhone) draft.receiverPhone = user.phone;
      if (!draft.receiverName) draft.receiverName = user.username || "Self";
    }
    const store_self = draft.isSelf && draft.receiverPhone === user.phone;

    if (!draft.receiverPhone || draft.receiverPhone.trim() === "") {
      req.flash("error", "Receiver phone is required.");
      return res.redirect("/mobile/send/step2");
    }

    // Generate customId
    
    let customId;
    let exists = true;

    while (exists) {
    customId = "P" + Math.random().toString(36).substring(2, 8).toUpperCase();
    exists = await Parcel2.exists({ customId });
  }


    let razorpayOrder = null;
    let razorpayPaymentLink = null;
    let status = "awaiting_drop";
    let paymentStatus = "completed";
   let expiresAt = new Date(Date.now() + 1 * 24 * 60 * 60 * 1000);


    // Handle both sender and receiver pay
    
      status = "awaiting_payment";
      paymentStatus = "pending";
      expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 hours
      razorpayOrder = await razorpay.orders.create({
        amount: Math.round(parseFloat(cost) * 100),
        currency: "INR",
        receipt: `parcel_${Date.now()}`,
        payment_capture: 1
      });


    //   razorpayLinkObject  = await razorpay.paymentLink.create({
    //   amount: Math.round(parseFloat(cost) * 100),
    //   currency: "INR",
    //   accept_partial: false,
    //   description: `Payment for Parcel ${customId}`,
    //   customer: {
    //     name: draft.receiverName,
    //     contact: draft.receiverPhone
    //   },
    //   notify: {
    //     sms: true,
    //     email: false
    //   },
    //   callback_url: `${process.env.BASE_URL}/mobile/payment/success-link?parcelId=${customId}`,
    //   callback_method: "get"
    // });
    
    // razorpayPaymentLink = razorpayLinkObject.short_url;

    const parcel = new Parcel2({
      ...draft,
      senderId: req.user._id,
      senderName: user.username,
      senderPhone: user.phone,
      receiverName: draft.receiverName,
      receiverPhone: draft.receiverPhone,
      recipientAddress: draft.recipientAddress,
      recipientPincode: draft.recipientPincode,
      selectedLocker: draft.selectedLocker,
      selectedLockerPincode: draft.selectedLockerPincode,
      accessCode,
      qrImage,
      store_self,
      lockerId: draft.lockerId || null,
      cost: cost.toString(),
      status,
      paymentStatus,
      droppedAt: null,
      expiresAt,
      compartmentId: null,
      razorpayOrderId: razorpayOrder?.id || null,
     razorpayPaymentLink: razorpayPaymentLink || null,
      customId
    });

    await parcel.save();
    req.session.inProgressParcelId = parcel._id;
    if(store_self){
      return res.render("mobile/parcel/self_payment", {
        parcel,
        razorpayKeyId: process.env.RAZORPAY_KEY_ID,
        orderId: razorpayOrder.id,
        amount: razorpayOrder.amount,
        currency: razorpayOrder.currency
      });
    }
      return res.render("mobile/parcel/payment", {
        parcel,
        razorpayKeyId: process.env.RAZORPAY_KEY_ID,
        orderId: razorpayOrder.id,
        amount: razorpayOrder.amount,
        currency: razorpayOrder.currency
      });
   

  } catch (error) {
    console.error("❌ Error in /send/step3:", error);
    req.flash("error", error.message || "Something went wrong.");
    res.redirect("/mobileDashboard");
  }
});

app.get("/mobile/parcel/:id/receiver-pay", isAuthenticated, async (req, res) => {
   const user = await User.findById(req.session.user._id).lean();
  if (!user) return res.redirect("/login");
  const parcel = await Parcel2.findById(req.params.id);
  if (!parcel) return res.status(404).send("Parcel not found");

  if (parcel.paymentStatus === "completed") {
    return res.send("This parcel is already paid.");
  }

  // Generate payment link only if not already generated
  if (!parcel.razorpayPaymentLink) {
    const razorpayPaymentLink = await razorpay.paymentLink.create({
      amount: Math.round(parseFloat(parcel.cost) * 100),
      currency: "INR",
      accept_partial: false,
      description: `Payment for Parcel ${parcel.customId}`,
      customer: {
        name: parcel.receiverName,
        contact: parcel.receiverPhone
      },
      notify: {
        sms: true,
        email: false
      },
      callback_url: `${process.env.BASE_URL}/mobile/payment/success-link?parcelId=${parcel._id}`,
      callback_method: "get"
    });

    // Save payment link
    parcel.razorpayPaymentLink = razorpayPaymentLink.short_url;
    parcel.status = "awaiting_payment";
    parcel.paymentStatus = "pending";
    await parcel.save();
  }

  // Render EJS page with the link
  res.render("mobile/showPaymentLink", {
    parcel,
    paymentLink: parcel.razorpayPaymentLink
  });
});




app.get("/mobile/payment/success-link", async (req, res) => {
  const {
    parcelId,
    razorpay_payment_id,
    razorpay_payment_link_id,
    razorpay_payment_link_status,
    razorpay_signature,
    customId
  } = req.query;

  try {

const parcel = await Parcel2.findOne({
  $or: [
    { _id: parcelId },         // This will work if parcelId is a valid ObjectId
    { customId: customId }
  ]
});

    

    // Only update if the payment was successful
    if (razorpay_payment_link_status === "paid") {
      parcel.paymentStatus = "completed"; 
      parcel.status = "awaiting_drop"; // or any next logical state
      parcel.razorpayPaymentId = razorpay_payment_id;
      parcel.razorpayPaymentLinkId = razorpay_payment_link_id;
      parcel.razorpaySignature = razorpay_signature;
      await parcel.save();

      return res.render("mobile/paymentSuccess", {
      parcel
    });
    } else {
      return res.status(400).send("Payment failed or not completed.");
    }
  } catch (err) {
    console.error("Payment success handler error:", err);
    res.status(500).send("Something went wrong processing your payment.");
  }
});


app.get("/mobile/send/estimate",isAuthenticated, async(req,res)=>{
   const user = await User.findById(req.session.user._id).lean();
  if (!user) return res.redirect("/login");
  try{
    const draft = req.session.parcelDraft;
    if(
      !draft ||
      !draft.selectedLockerPincode ||
      !draft.recipientPincode ||
      draft.receiverDeliveryMethod !== "address_delivery"
    ) {
      req.flash("error", "Incomplete data for delivery estimation");
      return res.redirect("/mobile/send/step2");
    }
    const token  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjcyODMwMzksInNvdXJjZSI6InNyLWF1dGgtaW50IiwiZXhwIjoxNzU1MTU4NzE0LCJqdGkiOiJyTHVTRlFnSHF2T2RaOFhXIiwiaWF0IjoxNzU0Mjk0NzE0LCJpc3MiOiJodHRwczovL3NyLWF1dGguc2hpcHJvY2tldC5pbi9hdXRob3JpemUvdXNlciIsIm5iZiI6MTc1NDI5NDcxNCwiY2lkIjo3MDUxNjYyLCJ0YyI6MzYwLCJ2ZXJib3NlIjpmYWxzZSwidmVuZG9yX2lkIjowLCJ2ZW5kb3JfY29kZSI6IiJ9.3x5fpkbgqJjHLhj2pimF_rSBnVk08OCP8cprFpHuVMk';

    const headers = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    };

    const params = new URLSearchParams({
      pickup_postcode: draft.selectedLockerPincode,
      delivery_postcode: draft.recipientPincode,
      weight: 1,
      cod: 0
    });

    const response = await axios.get(
      `https://apiv2.shiprocket.in/v1/external/courier/serviceability?${params.toString()}`,
      { headers }
    );

    let lockercost = getEstimatedCost(draft.size);
    const courierOptions = response.data.data.available_courier_companies;
    const bestOption = courierOptions.sort((a, b) => a.rate - b.rate)[0];
    if (!courierOptions || courierOptions.length === 0) {
      req.flash("error", "No delivery service available for the selected address.");
      return res.redirect("/mobile/send/step2");
    }

    res.render("mobile/parcel/estimate", {
      courier: bestOption,
      courierOptions,
      lockercost,
      totalCost: courierOptions.rate
    });
  }
  catch (err) {
    console.error("❌ Error fetching estimate:", err);
    req.flash("error", "Error fetching delivery estimate.");
    res.redirect("/mobile/send/step2");
  }
});


app.get("/mobile/payment/success", isAuthenticated, async (req, res) => {
  try {
    const { order_id, payment_id, signature } = req.query;
    const { parcelId, razorpay_payment_link_id, razorpay_payment_id, razorpay_payment_link_status } = req.query;

    // ✅ Case 1: Sender Pays (Order flow)
    if (order_id && payment_id && signature) {
      const generatedSignature = crypto
        .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
        .update(order_id + "|" + payment_id)
        .digest("hex");

      if (generatedSignature !== signature) {
        req.flash("error", "Payment verification failed.");
        return res.redirect("/mobileDashboard");
      }

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
        return res.redirect("/mobileDashboard");
      }

      delete req.session.parcelDraft;
      return res.redirect(`/mobile/parcel/${parcel._id}/success`);
    }

    // ✅ Case 2: Receiver Pays (Payment Link flow)
    if (parcelId && razorpay_payment_link_status === "paid") {
      const parcel = await Parcel2.findById(parcelId);
      if (!parcel) {
        req.flash("error", "Parcel not found.");
        return res.redirect("/mobileDashboard");
      }

      parcel.paymentStatus = "completed";
      parcel.status = "awaiting_drop";
      parcel.razorpayPaymentId = razorpay_payment_id;
      parcel.razorpayPaymentLinkStatus = "paid";
      await parcel.save();

      return res.redirect(`/mobile/parcel/${parcel._id}/success`);
    }

    req.flash("error", "Invalid payment callback.");
    res.redirect("/mobileDashboard");

  } catch (err) {
    console.error("❌ Payment success handler error:", err);
    req.flash("error", "Something went wrong during payment verification.");
    res.redirect("/mobileDashboard");
  }
});


app.get("/mobile/view/parcel/:id/success", async (req, res) => {
    const parcelid = req.params.id;
    const parcel = await Parcel2.findById(req.params.id);
    if (!parcel) return res.status(404).send("Parcel not found");
    
  res.render("mobile/parcel/success", { parcel });
});

app.get("/mobile/parcel/:id/success", async (req, res) => {

    const parcelid = req.params.id;
    const parcel = await Parcel2.findById(req.params.id);
    if (!parcel) return res.status(404).send("Parcel not found");
     await client.messages.create({
    to: `whatsapp:+91${parcel.senderPhone}`,
    from: 'whatsapp:+15558076515',
    contentSid: 'HX38edc7859ecff729dae14e0ce41923bb', 
    contentVariables: JSON.stringify({
      1: `${parcel.senderName}`, // Sender name
      2: `${parcelid}/qr` // Parcel ID
})
}).then(message => console.log('✅ WhatsApp Message Sent:', message.sid))
.catch(error => console.error('❌ WhatsApp Message Error:', error));


  res.render("mobile/parcel/success", { parcel });
});

//// STORE VIA LOCKER CATALOGUE

app.get("/mobile/send/select-locker/:lockerId",isAuthenticated, async(req,res) =>{



     const user = await User.findById(req.session.user._id).lean();
  if (!user) return res.redirect("/login");
  

  const lockerId = req.params.lockerId;
  const locker = await Locker.findOne({lockerId : lockerId});

  if(!locker){
    req.flash("error","Locker Not Found");
    return res.redirect("/mobile/store");
  }
    if (!user.phone) {
     
       req.session.pendingRedirectAfterPhoneLink = `/mobile/send/select-locker/${lockerId}`;
      req.flash("error", "Please verify your phone number to continue.");
      return res.redirect("/mobile/link-phone");
    }

  res.render("mobile/parcel/select-size", {locker});
});


app.post("/mobile/send/select-locker/:lockerId", isAuthenticated, async (req, res) => {
   const user = await User.findById(req.session.user._id).lean();
  if (!user) return res.redirect("/login");
  const lockerId = req.params.lockerId;
  const size = req.body.size;
  const locker = await Locker.findOne({ lockerId });
  if (!locker) {
    req.flash("error", "Locker not found");
    return res.redirect("/mobile/store");
  }
   
  
  req.session.parcelDraft = { 
    isSelf: true,
    type: "package",
    size: size,
    lockerId: locker.lockerId,
    location_id: locker.location?._id || null,
    lockerLat: locker.location?.lat,
    lockerLng: locker.location?.lng,
    description: "Stored via locker catalog",
    receiverName: req.user.username,
    receiverPhone: req.user.phone
  };

  res.redirect("/mobile/send/step3");

});


app.get("/mobile/incoming/:id/qr", async (req, res) => {
  const parcel = await Parcel2.findById(req.params.id).lean();
  const parcelLocker = parcel.lockerId || "";
  const accessCode = parcel.accessCode;
  let qrImage;
    
      qrImage = await QRCode.toDataURL(accessCode);
    


  if (!parcel) return res.status(404).send("Parcel not found");
  if (!parcel.qrImage)
    return res.status(400).send("No QR code saved for this parcel");
  res.render("mobile/qrPage", { parcel,qrImage });
});


app.post("/:parcelId/extend/create-order", async (req, res) => {
  try {
    const parcel = await Parcel.findById(req.params.parcelId);
    if (!parcel) return res.status(404).json({ error: "Parcel not found" });

    // Example pricing based on size
    let amount = 0;
    if (parcel.size === "small") amount = 30; // ₹20
    if (parcel.size === "medium") amount = 4000; // ₹40
    if (parcel.size === "large") amount = 6000; // ₹60

    const order = await razorpay.orders.create({
      amount: amount, // in paise
      currency: "INR",
      receipt: `extend_${parcel._id}_${Date.now()}`
    });

    res.json({
      key: process.env.RAZORPAY_KEY_ID,
      amount: order.amount,
      currency: order.currency,
      orderId: order.id
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create order" });
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

app.get("/location-select",isAuthenticated, async(req,res)=>{
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
      "locations-select",
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


        res.send(html);
      }
    );
  } catch (err) {
    console.error("Error loading locations:", err);
    res.status(500).send("Internal Server Error");
  }
})



app.get("/send/step2", isAuthenticated, async (req, res) => {
  await FunnelEvent.create({
    sessionId: req.sessionID,
    userId: req.user?._id || null,
    step: "send_parcel_clicked",
    timestamp: new Date()
  });
  const savedContacts = await Contact.find({ userId: req.user._id }).sort({ createdAt: -1 });
  const user = await User.findById(req.session.user._id);
  const size = req.query.size;
  const savedAddresses = await SavedAddress.find({ userId: req.user._id });
  const isSelf = req.query.self === 'true';
  if (!req.session.parcelDraft) req.session.parcelDraft = {};

  if (size) {
    req.session.parcelDraft.size = size;
    req.session.parcelDraft.type = "package";
    req.session.parcelDraft.description = "";
  }

  if (!user.phone) {
    // req.session.pendingRedirectAfterPhoneLink = `/send/step2${size ? `?size=${size}` : ""}`;
    req.flash("error", "Please verify your phone number to continue.");
    return res.redirect("/link-phone");
  }

  if (isSelf) {
    req.session.parcelDraft.receiverName = user.username || "Self";
    req.session.parcelDraft.receiverPhone = user.phone;
    req.session.parcelDraft.isSelf = true;
    console.log(user.phone);
    return res.redirect("/send/step3");
  }

  // 🆕 Fetch available lockers
  const lockers = await Locker.find({
  "compartments.isBooked": false
});

  // Render with lockers
  res.render("parcel/step2", { lockers, savedAddresses,savedContacts });
});

app.post("/send/step2", isAuthenticated, async (req, res) => {
  const {
    receiverName,
    receiverPhone,
    deliveryOption,
    receiverDeliveryMethod,
    recipientAddress,
    recipientPincode,
    selectedLocker,
    saveContact,
    
  } = req.body;
   if (saveContact === 'true' && receiverName && receiverPhone) {
  try {
    // Check if contact already exists for this user
    const existingContact = await Contact.findOne({
      userId: req.user._id,
      phone: receiverPhone.trim(),
    });

    if (!existingContact) {
      const newContact = new Contact({
        userId: req.user._id,
        name: receiverName.trim(),
        phone: receiverPhone.trim(),
      });
      await newContact.save();
    } else {
      console.log("Contact already exists. Skipping save.");
    }
  } catch (err) {
    console.error("Error saving contact:", err);
  }
}

  const user = await User.findById(req.session.user._id);
  
  if (!req.session.parcelDraft) req.session.parcelDraft = {};

  // Self Flow (Store for Myself)
  if (deliveryOption === "self") {
    req.session.parcelDraft.isSelf = true;
    req.session.parcelDraft.receiverName = user.username || "Self";
    req.session.parcelDraft.receiverPhone = user.phone || "";
    req.session.parcelDraft.receiverDeliveryMethod = "self_pickup";
  } else {
    // Validate name/phone
    if (!receiverName || !receiverPhone) {
      req.flash("error", "Please enter both name and phone for the recipient.");
      return res.redirect("/send/step2");
    }

    if (!receiverDeliveryMethod) {
      req.flash("error", "Please select how the receiver will receive the parcel.");
      return res.redirect("/send/step2");
    }

    req.session.parcelDraft.isSelf = false;
    req.session.parcelDraft.receiverName = receiverName;
    req.session.parcelDraft.receiverPhone = receiverPhone;
    req.session.parcelDraft.receiverDeliveryMethod = receiverDeliveryMethod;
    req.session.parcelDraft.paymentOption = "sender_pays";
    req.session.parcelDraft.status = "awaiting_drop";
    // 🔁 Extra logic for address delivery
    if (receiverDeliveryMethod === "address_delivery") {
      if (!recipientAddress || !recipientPincode || !selectedLocker) {
        req.flash("error", "Please fill in recipient address, pincode, and select a dispatch locker.");
        return res.redirect("/send/step2");
      }if (!selectedLocker || !mongoose.Types.ObjectId.isValid(selectedLocker)) {
  req.flash("error", "Please select a valid locker for dispatch.");
  return res.redirect("/send/step2");
}
      const locker = await Locker.findById(selectedLocker);
      const lockerPincode = locker?.location?.pincode || "";
      // Save address and locker info
      req.session.parcelDraft.recipientAddress = recipientAddress;
      req.session.parcelDraft.recipientPincode = recipientPincode;
      req.session.parcelDraft.selectedLocker = selectedLocker;
      req.session.parcelDraft.selectedLockerPincode =lockerPincode;
      if (receiverDeliveryMethod === "address_delivery") {
  // Save address to DB (if not already saved)
  

if (
  req.body.saveAddress === "true" &&
  req.body.recipientAddress &&
  req.body.recipientPincode &&
  req.body.receiverName
) {
  const alreadyExists = await SavedAddress.findOne({
    userId: req.user._id,
    address: req.body.recipientAddress.trim(),
    pincode: req.body.recipientPincode.trim()
  });

  if (!alreadyExists) {
    await SavedAddress.create({
      userId: req.user._id,
      address: req.body.recipientAddress.trim(),
      pincode: req.body.recipientPincode.trim(),
      ownerName : req.body.receiverName,
      label: "Saved on " + new Date().toLocaleDateString()
    });
  }
}

}

    }
  }

  if (receiverDeliveryMethod === "address_delivery") {
  return res.redirect("/send/estimate");
} else {
  return res.redirect("/send/step3");
}

});



app.get("/send/estimate", isAuthenticated, async (req, res) => {
  try {
    const draft = req.session.parcelDraft;

    if (
      !draft ||
      !draft.selectedLockerPincode ||
      !draft.recipientPincode ||
      draft.receiverDeliveryMethod !== "address_delivery"
    ) {
      req.flash("error", "Incomplete data for delivery estimation.");
      return res.redirect("/send/step2");
    }

    // Prepare request to Shiprocket
    const token  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjcyODMwMzksInNvdXJjZSI6InNyLWF1dGgtaW50IiwiZXhwIjoxNzU0MTUwODA1LCJqdGkiOiJvc1R3VFNWWFQ4YnNObG9GIiwiaWF0IjoxNzUzMjg2ODA1LCJpc3MiOiJodHRwczovL3NyLWF1dGguc2hpcHJvY2tldC5pbi9hdXRob3JpemUvdXNlciIsIm5iZiI6MTc1MzI4NjgwNSwiY2lkIjo3MDUxNjYyLCJ0YyI6MzYwLCJ2ZXJib3NlIjpmYWxzZSwidmVuZG9yX2lkIjowLCJ2ZW5kb3JfY29kZSI6IiJ9.kds27l6abl8baauEq4PvpbtVXHUmUFkw7FBsjZ8ZYsY';
    
    const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
   const params = new URLSearchParams({
    pickup_postcode: draft.selectedLockerPincode,
    delivery_postcode: draft.recipientPincode,
    weight: 1,
    cod: 0
  });
    
    const response = await axios.get(
      `https://apiv2.shiprocket.in/v1/external/courier/serviceability?${params.toString()}`,
      { headers }
    );
  
    let lockercost = getEstimatedCost(draft.size);
    const courierOptions = response.data.data.available_courier_companies;
      const bestOption = courierOptions.sort((a, b) => a.rate - b.rate)[0];
    if (!courierOptions || courierOptions.length === 0) {
      req.flash("error", "No delivery service available for the selected address.");
      return res.redirect("/send/step2");
    }
    
    // Show estimate page
    res.render("parcel/estimate", {
      courier: bestOption,
      courierOptions,
      lockercost,
      totalCost: courierOptions.rate
    });

  } catch (err) {
    console.error("❌ Error fetching estimate:", err);
    req.flash("error", "Error fetching delivery estimate.");
    res.redirect("/send/step2");
  }
});


app.get("/send/step3", isAuthenticated, async (req, res) => {
  try {
     
    const { rate } = req.query;
    const draft = req.session.parcelDraft;
    console.log(rate);
    const lockerId = draft.selectedLocker; // because that's where you're storing it
    const prestatus = draft.status;
    const user = await User.findById(req.session.user._id);
    const accessCode = Math.floor(100000 + Math.random() * 900000).toString();
    let cost = getEstimatedCost(draft.size);
    if (draft.receiverDeliveryMethod === "address_delivery") {
      cost += parseFloat(rate); // Add delivery + platform fee
    }

    let qrImage;
    if (lockerId) {
      qrImage = await QRCode.toDataURL(JSON.stringify({ accessCode, lockerId,prestatus }));
    } else {
      qrImage = await QRCode.toDataURL(JSON.stringify({ accessCode,prestatus }));
    }

    let status = "awaiting_drop";
    let paymentStatus = "completed";
    let expiresAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
    let razorpayOrder = null;

    // Always use "sender_pays" now
    draft.paymentOption = "sender_pays";
    status = "awaiting_payment";
    paymentStatus = "pending";
    expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);

    razorpayOrder = await razorpay.orders.create({
      amount: Math.round(parseFloat(cost) * 100),
      currency: "INR",
      receipt: `parcel_${Date.now()}`,
      payment_capture: 1,
    });

    if (draft.isSelf) {
      if (!draft.receiverPhone) draft.receiverPhone = user.phone;
      if (!draft.receiverName) draft.receiverName = user.username || "Self";
    }

    if (!draft.receiverPhone || draft.receiverPhone.trim() === "") {
      req.flash("error", "Receiver phone is required.");
      return res.redirect("/send/step2");
    }

    const parcel = new Parcel2({
      
      ...draft,
      senderId: req.user._id,
      senderName: user.username,
      senderPhone: user.phone,
      receiverName: draft.receiverName,
      receiverPhone: draft.receiverPhone,
       // Save address and locker info
      recipientAddress : draft.recipientAddress,
    recipientPincode : draft.recipientPincode,
    selectedLocker : draft.selectedLocker,
    selectedLockerPincode : draft.selectedLockerPincode,
      accessCode,
      qrImage,
      lockerId: draft.lockerId || null,
      cost: cost.toString(),
      status,
      paymentStatus,
      droppedAt: null,
      expiresAt,
      compartmentId: null,
      razorpayOrderId: razorpayOrder?.id || null,
    });
    req.session.inProgressParcelId = parcel._id;
   await parcel.save();


// funnel log
await FunnelEvent.create({
  sessionId: req.sessionID,
  step: 'step3_complete',
  timestamp: new Date(),
});
    // funnel log
    await FunnelEvent.create({
      sessionId: req.sessionID,
      step: 'step3_complete',
      timestamp: new Date(),
    });
    delete req.session.inProgressParcelId;
    // Redirect directly to Razorpay payment page
    return res.render("parcel/payment", {
      parcel,
      razorpayKeyId: process.env.RAZORPAY_KEY_ID,
      orderId: razorpayOrder.id,
      amount: razorpayOrder.amount,
      currency: razorpayOrder.currency,
    });

  } catch (error) {
    console.error("❌ Error in /send/step3:", error);
    req.flash("error", "Something went wrong. Please try again.");
    res.redirect("/dashboard");
  }
});

app.get("/parcel/:id/modify",async(req,res)=>{
    const parcel = await Parcel2.findById(req.params.id).lean();
  const parcelLocker = parcel.lockerId || "";
  const accessCode = parcel.accessCode;
  const modifystatus = "modify"
  let qrImage;
    if (parcelLocker != "") {
      qrImage = await QRCode.toDataURL(JSON.stringify({ accessCode, parcelLocker, modifystatus }));
    } else {
      qrImage = await QRCode.toDataURL(JSON.stringify({ accessCode }));
    }
  if (!parcel) return res.status(404).send("Parcel not found");
  if (!parcel.qrImage)
    return res.status(400).send("No QR code saved for this parcel");
  res.render("qrPage", { parcel,qrImage });
})



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
  delete req.session.parcelDraft;
  res.redirect(`/parcel/${parcel._id}/success`);
});











function getEstimatedCost(size) {
  if (size === "small") return 10;
  if (size === "medium") return 20;
  return 30;
}

app.get("/parcel/:id/move/confirm", isAuthenticated, async (req, res) => {
  const { moveDetails } = req.session;
  if (!moveDetails || moveDetails.parcelId !== req.params.id) {
    req.flash("error", "No move details found.");
    return res.redirect("/dashboard");
  }

  const {
    fromPincode,
    toPincode,
    parcelWeight,
    parcelSize
  } = moveDetails;

  const sizeMap = {
    small: { length: 10, breadth: 10, height: 10 },
    medium: { length: 20, breadth: 15, height: 15 },
    large: { length: 30, breadth: 20, height: 20 }
  };

  const { length, breadth, height } = sizeMap[parcelSize] || sizeMap.small;

  try {
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjcyODMwMzksInNvdXJjZSI6InNyLWF1dGgtaW50IiwiZXhwIjoxNzU0MTUwODA1LCJqdGkiOiJvc1R3VFNWWFQ4YnNObG9GIiwiaWF0IjoxNzUzMjg2ODA1LCJpc3MiOiJodHRwczovL3NyLWF1dGguc2hpcHJvY2tldC5pbi9hdXRob3JpemUvdXNlciIsIm5iZiI6MTc1MzI4NjgwNSwiY2lkIjo3MDUxNjYyLCJ0YyI6MzYwLCJ2ZXJib3NlIjpmYWxzZSwidmVuZG9yX2lkIjowLCJ2ZW5kb3JfY29kZSI6IiJ9.kds27l6abl8baauEq4PvpbtVXHUmUFkw7FBsjZ8ZYsY'
    const { data } = await axios.post("https://apiv2.shiprocket.in/v1/external/courier/serviceability/",
      {
        pickup_postcode: fromPincode,
        delivery_postcode: toPincode,
        cod: 0,
        weight: parcelWeight,
        length,
        breadth,
        height
      },
      {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    );

    const parcel = await Parcel2.findById(req.params.id);
    res.render("move_confirm", {
      parcel,
      deliveryOptions: data.data,
      fromPincode,
      toPincode
    });
  } catch (err) {
    console.error("Shiprocket API error:", err?.response?.data || err.message);
    req.flash("error", "Could not fetch delivery rates.");
    return res.redirect("/dashboard");
  }
});

app.post("/parcel/:id/move/confirm", isAuthenticated, async (req, res) => {
  const { moveDetails } = req.session;
  const { courier_code } = req.body;

  if (!moveDetails) return res.redirect("/dashboard");

  await Parcel2.findByIdAndUpdate(req.params.id, {
    status: "in_transit",
    deliveryPartner: courier_code,
    destinationLockerId: moveDetails.newLockerId
  });

  // Optional: create a record in CourierMovement table

  req.flash("success", "Move initiated. Parcel marked in transit.");
  res.redirect("/dashboard");
});
















app.get("/api/couriers", async (req, res) => {
  const couriers = [
    { name: "Delhivery", cost: 30, eta: "2-3 days" },
    { name: "BlueDart", cost: 50, eta: "1-2 days" },
    { name: "Xpressbees", cost: 40, eta: "2 days" },
  ];
  res.json(couriers);
});


// GET /services
app.get("/services", isAuthenticated, async (req, res) => {
  const userPhone = req.user.phone;

  const parcels = await Parcel2.find({
    receiverPhone: userPhone,
    status: "awaiting_pick",
  });

  const lockers = await Locker.find();

  res.render("services", { parcels, lockers,  activePage: "services" });
});



app.get("/services/transfer", isAuthenticated, async (req, res) => {
  const userId = req.session.user._id;

  const parcels = await Parcel2.find({
    senderId: userId,
    status: "awaiting_pick",
  });

  res.render("transferList", { parcels });
});





// utils/shiprocket.js

require("dotenv").config();

async function generateShiprocketToken() {
  try {
    const response = await axios.post("https://apiv2.shiprocket.in/v1/external/auth/login", {
      email: process.env.SHIPROCKET_EMAIL,
      password: process.env.SHIPROCKET_API_KEY,
    });

    const token = response.data.token;
    console.log("✅ Shiprocket token:", token);
    return token;
  } catch (err) {
    console.error("❌ Failed to generate Shiprocket token:", err.response?.data || err.message);
    return null;
  }
}













async function getShippingRates(fromPin, toPin, weight) {
   const token = " eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjcyODMwMzksInNvdXJjZSI6InNyLWF1dGgtaW50IiwiZXhwIjoxNzU0MTUwODA1LCJqdGkiOiJvc1R3VFNWWFQ4YnNObG9GIiwiaWF0IjoxNzUzMjg2ODA1LCJpc3MiOiJodHRwczovL3NyLWF1dGguc2hpcHJvY2tldC5pbi9hdXRob3JpemUvdXNlciIsIm5iZiI6MTc1MzI4NjgwNSwiY2lkIjo3MDUxNjYyLCJ0YyI6MzYwLCJ2ZXJib3NlIjpmYWxzZSwidmVuZG9yX2lkIjowLCJ2ZW5kb3JfY29kZSI6IiJ9.kds27l6abl8baauEq4PvpbtVXHUmUFkw7FBsjZ8ZYsY"
  if (!token) return null;

  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };

    const params = new URLSearchParams({
    pickup_postcode: fromPin,
    delivery_postcode: toPin,
    weight: weight,
    cod: 0
  });

   try {
    const res = await axios.get(
      `https://apiv2.shiprocket.in/v1/external/courier/serviceability?${params.toString()}`,
      { headers }
    );
    return res.data;
  } catch (err) {
    console.error("❌ Error fetching Shiprocket rates:", err.response?.data || err.message);
    return null;
  }
}





















app.get("/parcel/:id/move", isAuthenticated, async (req, res) => {
  const parcelId = req.params.id;
  const parcel = await Parcel2.findById(parcelId);

  if (!parcel || parcel.status !== "awaiting_pick") {
    req.flash("error", "Parcel is not eligible for moving.");
    return res.redirect("/services/transfer");
  }

  const lockers = await Locker.find({}); // You can filter by compatibility later

  res.render("moveLocker", { parcel, lockers });
});
app.post("/parcel/:id/move", isAuthenticated, async (req, res) => {
  const parcelId = req.params.id;
  const { newLockerId } = req.body;

  const parcel = await Parcel2.findById(parcelId);
  const newLocker = await Locker.findOne({ lockerId: newLockerId });
  const oldLocker = await Locker.findOne({ lockerId: parcel.lockerId });

  if (!parcel || !newLocker || !oldLocker) {
    req.flash("error", "Invalid parcel or locker.");
    return res.redirect("/services/transfer");
  }

  // Estimate cost
  try {
    const response = await getShippingRates(
  oldLocker.location.pincode,
  newLocker.location.pincode,
  parcel.size === "small" ? 0.5 : parcel.size === "medium" ? 1.5 : 3
);

if (!response || !response.data || !response.data.available_courier_companies) {
  req.flash("error", "Could not fetch courier options. Please try again.");
  return res.redirect("/dashboard");
}
let courierOptions = response.data.available_courier_companies;
courierOptions.sort((a, b) => a.rate - b.rate);

res.render("parcel/select-courier", {
  parcel,
  courierOptions,
  fromLocker: oldLocker,
  toLocker: newLocker
});



  } catch (err) {
    console.error("Error fetching Shiprocket rates:", err.message);
    req.flash("error", err.message);
    res.redirect("/dashboard");
  }
});


app.post("/parcel/:id/confirm-move", isAuthenticated, async (req, res) => {
  const { newLockerId, courierIndex } = req.body;
  const parcel = await Parcel2.findById(req.params.id);
  const newLocker = await Locker.findOne({ lockerId: newLockerId });

  if (!parcel || !newLocker) {
    req.flash("error", "Invalid parcel or locker.");
    return res.redirect("/services/transfer");
  }

  const courierName = req.body[`courier_${courierIndex}_name`];
  const rate = req.body[`courier_${courierIndex}_rate`];
  const eta = req.body[`courier_${courierIndex}_eta`];

  parcel.status = "in_transit";
  parcel.transitInfo = {
    fromLockerId: parcel.lockerId,
    toLockerId: newLockerId,
    startedAt: new Date(),
    courier: courierName,
    rate,
    etd: eta,
  };
  
  await parcel.save();

  // Send WhatsApp
  await client.messages.create({
    to: `whatsapp:+91${parcel.receiverPhone}`,
    from: 'whatsapp:+15558076515',
    contentSid: 'HX3a4f9ef7ea9e8469c8811204abc8599b',
    contentVariables: JSON.stringify({
      1: parcel.receiverName,
      2: parcel.senderName,
      3: courierName,
      4: newLocker.location.address,
      5: `Within ${eta} Day(s)`,
    }),
  });

  req.flash("success", `Parcel marked in transit via ${courierName}`);
  res.redirect("/dashboard");
});








app.post("/parcel/:id/move", isAuthenticated, async (req, res) => {
  const parcelId = req.params.id;
  const { newLockerId } = req.body;

  const parcel = await Parcel2.findById(parcelId);
  const newLocker = await Locker.findOne({ lockerId: newLockerId });
 const lockerAddress = locker?.location?.address;
  if (!parcel || !newLocker) {
    req.flash("error", "Invalid parcel or locker.");
    return res.redirect("/services/transfer");
  }

  // Mark as in transit
  parcel.status = "in_transit";
  parcel.transitInfo = {
    fromLockerId: parcel.lockerId,
    toLockerId: newLockerId,
    startedAt: new Date()
  };
  await parcel.save();

 // Optional: Notify receiver via WhatsApp that it is on the way
  await client.messages.create({
  to: `whatsapp:+91${parcel.receiverPhone}`,
  from: 'whatsapp:+15558076515', // your approved Twilio number
  contentSid: 'HX62901ad08f763acb2e42347ce24e529a',
  contentVariables: JSON.stringify({
    1: parcel.receiverName,
    2: parcel.senderName,
    3: parcel.type || "Package",
    4: newLocker.location.address,  // replace with locker address
    5: "Today by 6 PM" // ETA or calculated estimate
  }),
});

  req.flash("success", "Parcel marked as in transit.");
  res.redirect("/dashboard");
});

















app.get("/send/select-locker/:lockerId", isAuthenticated, async (req, res) => {
  const lockerId = req.params.lockerId;
  const locker = await Locker.findOne({ lockerId: lockerId });

  if (!locker) {
    req.flash("error", "Locker not found");
    return res.redirect("/locations");
  }

  res.render("parcel/select-size", { locker });
});


app.post("/send/select-locker/:lockerId", isAuthenticated, async (req, res) => {
  const lockerId = req.params.lockerId;
  const size = req.body.size;

  const locker = await Locker.findOne({ lockerId });

  if (!locker) {
    req.flash("error", "Locker not found");
    return res.redirect("/locations");
  }

  req.session.parcelDraft = { 
    isSelf: true,
    type: "package",
    size: size,
    paymentOption: "sender_pays",
    lockerId: locker.lockerId,
    location_id: locker.location?._id || null,
    lockerLat: locker.location?.lat,
    lockerLng: locker.location?.lng,
    description: "Stored via locker catalog",
    receiverName: req.user.username,
    receiverPhone: req.user.phone
  };

  res.redirect("/send/step3");
});






// app.get("/send/select-locker/:lockerId", isAuthenticated, async (req, res) => {
//   const lockerId = req.params.lockerId;
//   const locker = await Locker.findOne({ lockerId: lockerId });

//   if (!locker) {
//     req.flash("error", "Locker not found");
//     return res.redirect("/locations");
//   }

//   // Initialize parcelDraft with locker details
//   req.session.parcelDraft = {
//     isSelf: true,
//     type: "package",
//     size: "small", // Default; you can allow changing later
//     paymentOption: "sender_pays",
//     lockerId: locker.lockerId,
//     location_id: locker.location?._id || null,
//     lockerLat: locker.location?.lat,
//     lockerLng: locker.location?.lng,
//     description: "Stored via locker catalog",
//     receiverName: req.user.username,
//     receiverPhone: req.user.phone
//   };

//   res.redirect("/send/step3");
// });
const UserAction = require('./models/userAction.js');

app.post("/analytics/user-action", async (req, res) => {
  const { step, method, path } = req.body;
  try{
  await UserAction.create({
    step,
    method,
    path,
    sessionId: req.sessionID,
    userId: req.session?.user?._id || null
  });
} catch(err){
  console.log(err);
}
  res.sendStatus(200);
});
app.get("/parcel/my-awaiting-drop", isAuthenticated, async (req, res) => {
  const parcels = await Parcel2.find({
    senderId: req.user._id,
    status: "awaiting_drop"
  });
  res.render("parcel/my-awaiting-drop", { parcels });
});


// Show form to reassign parcel
app.get("/parcel/:id/transfer", isAuthenticated, async (req, res) => {
  const parcel = await Parcel2.findById(req.params.id);
  if (!parcel || parcel.senderId.toString() !== req.user._id.toString()) {
    req.flash("error", "Parcel not found or unauthorized.");
    return res.redirect("/dashboard");
  }
  res.render("parcel/transfer", { parcel });
});

// Handle transfer POST
app.post("/parcel/:id/transfer", isAuthenticated, async (req, res) => {
  const { receiverName, receiverPhone } = req.body;
  const parcel = await Parcel2.findById(req.params.id);

  if (!parcel || parcel.senderId.toString() !== req.user._id.toString()) {
    req.flash("error", "Unauthorized action.");
    return res.redirect("/dashboard");
  }

  parcel.receiverName = receiverName;
  parcel.receiverPhone = receiverPhone;
  parcel.isSelf = false; // clear self mode
  await parcel.save();

  await FunnelEvent.create({
    sessionId: req.sessionID,
    step: "transfer_ownership",
    parcelId: parcel._id,
    timestamp: new Date(),
  });

  req.flash("success", "Ownership transferred successfully.");
  res.redirect("/dashboard");
});



app.get("/action_funnel", async (req, res) => {
  const now = new Date();

  const todayStart = new Date(now.setHours(0, 0, 0, 0));
  const todayEnd = new Date(todayStart);
  todayEnd.setDate(todayEnd.getDate() + 1);

  const yesterdayStart = new Date(todayStart);
  yesterdayStart.setDate(yesterdayStart.getDate() - 1);
  const yesterdayEnd = new Date(todayStart);

  const [todayRaw, yesterdayRaw] = await Promise.all([
    UserAction.aggregate([
      { $match: { timestamp: { $gte: todayStart, $lt: todayEnd } } },
      { $group: { _id: "$step", count: { $sum: 1 } } }
    ]),
    UserAction.aggregate([
      { $match: { timestamp: { $gte: yesterdayStart, $lt: yesterdayEnd } } },
      { $group: { _id: "$step", count: { $sum: 1 } } }
    ])
  ]);

  const combineSteps = (raw) => {
    const result = {
      not_logged_in: 0,
      logged_in: 0,
      dashboard: 0,
      send_step_2: 0,
      payment_stage: 0,
      payment_completed: 0,
      parcel_booked: 0,
      abandoned_login: 0
    };

    let loginPage = 0;
    let loginTotal = 0;

    raw.forEach(({ _id, count }) => {
      if (_id === "login_page") {
        result.not_logged_in += count;
        loginPage = count;
      } else if (_id === "login_google" || _id === "login_phone") {
        result.logged_in += count;
        loginTotal += count;
      } else if (result[_id] !== undefined) {
        result[_id] = count;
      }
    });

    result.abandoned_login = Math.max(loginPage - loginTotal, 0);
    return result;
  };

  const todayData = combineSteps(todayRaw);
  const yesterdayData = combineSteps(yesterdayRaw);

  const steps = [
    "not_logged_in",
    "logged_in",
    "abandoned_login",
    "dashboard",
    "send_step_2",
    "payment_stage",
    "payment_completed",
    "parcel_booked"
  ];

  const funnel = steps.map(step => ({
    step,
    today: todayData[step] || 0,
    yesterday: yesterdayData[step] || 0
  }));

  res.render("funnelAction", { funnel });
});







app.get("/receiver/:parcelId/update-address", async (req, res) => {
  const parcel = await Parcel2.findById(req.params.parcelId);
  if (!parcel) {
    return res.status(404).send("Parcel not found");
  }
  res.render("receiver/update-address", { parcel });
});

app.post("/receiver/:parcelId/update-address", async (req, res) => {
  const { receiverName, receiverPhone, deliveryAddress } = req.body;

  await Parcel2.findByIdAndUpdate(req.params.parcelId, {
    receiverName,
    receiverPhone,
    "transitInfo.recipientAddress": deliveryAddress,
    status: "awaiting_pick"
  });

  res.render("receiver/success", {
    message: "Your address has been updated. Your parcel will be dispatched shortly."
  });
});

app.get("/parcel/view/:id/success", async (req, res) => {
    const parcelid = req.params.id;
  const parcel = await Parcel2.findById(req.params.id);
  if (!parcel) return res.status(404).send("Parcel not found");
  res.render("parcel/successView", { parcel });
});
app.get("/:id/qrpage",async(req,res)=>{
  const parcel = await Parcel2.findById(req.params.id);
   if (!parcel) return res.status(404).send("Parcel not found");
    res.render("parcel/success", { parcel });

})
app.get("/parcel/:id/success", async (req, res) => {
    const user = await User.findById(req.session.user._id);
    const parcelid = req.params.id;
  const parcel = await Parcel2.findById(req.params.id);
  if (!parcel) return res.status(404).send("Parcel not found");
     await client.messages.create({
  to: `whatsapp:+91${user.phone}`,
  from: 'whatsapp:+15558076515',
  contentSid: 'HX8dc7a5b23a3a6a2a7ce8a4d2e577ac3c', 
  contentVariables: JSON.stringify({
  1: `${user.username}`, // Sender name
  2: `${parcelid}/qrpage` // Parcel ID
})// Template SID
}).then(message => console.log('✅ WhatsApp Message Sent:', message.sid))
.catch(error => console.error('❌ WhatsApp Message Error:', error));


  res.render("parcel/success", { parcel });
});



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
    const user  = await User.find({ _id : req.user._id})
    const parcels = await Parcel2.find({ senderName : user.username  })
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