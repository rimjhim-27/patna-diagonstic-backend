// routes/admin.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Booking = require('../models/booking');
const User = require('../models/Users');

// Middleware to check admin role
const adminCheck = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ msg: 'Unauthorized' });
  }
  next();
};

// Get all bookings
router.get('/bookings', auth, adminCheck, async (req, res) => {
  try {
    const bookings = await Booking.find()
      .populate('user', 'name email phone')
      .populate('service', 'name price');
    res.json(bookings);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Update booking status
router.put('/bookings/:id', auth, adminCheck, async (req, res) => {
  try {
    const { status } = req.body;
    
    const booking = await Booking.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );

    if (!booking) {
      return res.status(404).json({ msg: 'Booking not found' });
    }

    res.json(booking);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get all users
router.get('/users', auth, adminCheck, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;