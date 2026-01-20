require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const Trip = require('./models/Trip');

const app = express();
const JWT_SECRET = 'super_secret_bionic_key_change_this_in_prod'; // Security Key

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to DB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error(err));

// --- MIDDLEWARE: The Gatekeeper ---
// This checks if the user sent a valid Token. If not, it blocks the request.
const auth = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

  try {
    // Verify token (remove "Bearer " part if present, usually handled by client)
    const decoded = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
    req.user = decoded; // Add the user ID to the request object
    next();
  } catch (e) {
    res.status(400).json({ msg: 'Token is not valid' });
  }
};

// --- AUTH ROUTES ---

// 1. Register User
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Check if user exists
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User already exists' });

    // Create new user
    user = new User({ username, email, password });

    // Hash Password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    await user.save();

    // Create Token immediately so they don't have to login again
    const payload = { user: { id: user.id } };
    jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
      if (err) throw err;
      res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
    });

  } catch (err) {
    console.error(err.message);
    if (err.name === 'ValidationError') return res.status(400).json({ msg: 'Invalid Email Format' });
    res.status(500).send('Server Error');
  }
});

// 2. Login User
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check for user
    let user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid Credentials' });

    // Check Password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid Credentials' });

    // Return Token
    const payload = { user: { id: user.id } };
    jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
      if (err) throw err;
      res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
    });

  } catch (err) {
    res.status(500).send('Server Error');
  }
});

// 3. Get User Data (For the Config Panel)
app.get('/api/auth/user', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.user.id).select('-password'); // Don't return the password
    res.json(user);
  } catch (err) {
    res.status(500).send('Server Error');
  }
});

// --- TRIP ROUTES (PROTECTED) ---

// Get Trips (Only for the logged-in user)
app.get('/api/trips', auth, async (req, res) => {
  try {
    // req.user.user.id comes from the Token middleware
    const trips = await Trip.find({ user: req.user.user.id });
    res.json(trips);
  } catch (err) {
    res.status(500).send('Server Error');
  }
});

// Create Trip (Attach user ID)
app.post('/api/trips', auth, async (req, res) => {
  const { destination, budget, startDate } = req.body;
  try {
    const newTrip = new Trip({
      destination,
      budget,
      startDate,
      user: req.user.user.id // <--- Link trip to user
    });
    const trip = await newTrip.save();
    res.json(trip);
  } catch (err) {
    res.status(500).send('Server Error');
  }
});

// Add Expense
app.post('/api/trips/:id/expenses', auth, async (req, res) => {
  try {
    const trip = await Trip.findById(req.params.id);

    // Security Check: Does this trip belong to the logged-in user?
    if (trip.user.toString() !== req.user.user.id) {
      return res.status(401).json({ msg: 'Not authorized' });
    }

    trip.expenses.push(req.body);
    await trip.save();
    res.json(trip);
  } catch (err) {
    res.status(500).send('Server Error');
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Bionic Server running on port ${PORT}`));