const express = require("express");
const router = express.Router();
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const connectToDatabase = require("../models/db");
const pino = require("pino");

dotenv.config();

const logger = pino();
const JWT_SECRET = process.env.JWT_SECRET;

// --------------------
// Register Route
// --------------------
router.post("/register", async (req, res) => {
  try {
    const db = await connectToDatabase();
    const collection = db.collection("users");

    const existingEmail = await collection.findOne({ email: req.body.email });

    if (existingEmail) {
      logger.error("Email already exists");
      return res.status(400).json({ error: "Email already exists" });
    }

    const salt = await bcryptjs.genSalt(10);
    const hash = await bcryptjs.hash(req.body.password, salt);

    const newUser = await collection.insertOne({
      email: req.body.email,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      password: hash,
      createdAt: new Date(),
    });

    const payload = {
      user: {
        id: newUser.insertedId.toString(),
      },
    };

    const authtoken = jwt.sign(payload, JWT_SECRET);
    logger.info("User registered successfully");

    res.json({
      authtoken,
      email: req.body.email,
    });
  } catch (e) {
    logger.error("Register error: " + e.message);
    res.status(500).send("Internal server error");
  }
});

// --------------------
// Login Route
// --------------------
router.post("/login", async (req, res) => {
  try {
    const db = await connectToDatabase();
    const collection = db.collection("users");

    const theUser = await collection.findOne({ email: req.body.email });

    if (!theUser) {
      logger.error("User not found");
      return res.status(404).json({ error: "User not found" });
    }

    const isMatch = await bcryptjs.compare(req.body.password, theUser.password);

    if (!isMatch) {
      logger.error("Passwords do not match");
      return res.status(401).json({ error: "Incorrect password" });
    }

    const userName = theUser.firstName;
    const userEmail = theUser.email;

    const payload = {
      user: {
        id: theUser._id.toString(),
      },
    };

    const authtoken = jwt.sign(payload, JWT_SECRET);
    logger.info("User logged in successfully");

    res.json({ authtoken, userName, userEmail });
  } catch (e) {
    logger.error("Login error: " + e.message);
    res.status(500).send("Internal server error");
  }
});

module.exports = router;
