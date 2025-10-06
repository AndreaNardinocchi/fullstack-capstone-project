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

// {Insert it along with other imports} Task 1: Use the `body`,`validationResult` from `express-validator` for input validation
const { body, validationResult } = require("express-validator");

router.put("/update", async (req, res) => {
  // Task 2: Validate the input using `validationResult` and return approiate message if there is an error.
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.error("Validation errors in update request", errors.array());
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Task 3: Check if `email` is present in the header and throw an appropriate error message if not present.

    const email = req.headers.email;

    if (!email) {
      logger.error("Email not found in the request headers");
      return res
        .status(400)
        .json({ error: "Email not found in the request headers" });
    }
    // Task 4: Connect to MongoDB
    const db = await connectToDatabase();
    const collection = db.collection("users");
    // Task 5: find user credentials in database
    const existingUser = await collection.findOne({ email });

    existingUser.updatedAt = new Date();

    // Task 6: update user credentials in database
    const updatedUser = await collection.findOneAndUpdate(
      { email },
      { $set: existingUser },
      { returnDocument: "after" }
    );
    // Task 7: create JWT authentication using secret key from .env file
    const payload = {
      user: {
        id: updatedUser._id.toString(),
      },
    };

    const authtoken = jwt.sign(payload, JWT_SECRET);

    res.json({ authtoken });
  } catch (e) {
    return res.status(500).send("Internal server error");
  }
});

module.exports = router;
