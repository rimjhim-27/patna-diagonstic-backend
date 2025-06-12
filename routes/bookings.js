// routes/bookings.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Booking = require('../models/booking');
const Service = require('../models/Services');

// Create a new booking
router.post('/', auth, async (req, res) => {
  try {
    const { serviceId, bookingDate, timeSlot, address } = req.body;
    
    // Verify service exists
    const service = await Service.findById(serviceId);
    if (!service) {
      return res.status(404).json({ msg: 'Service not found' });
    }

    // Create new booking
    const newBooking = new Booking({
      user: req.user.id,
      service: serviceId,
      bookingDate,
      timeSlot,
      address
    });

    const booking = await newBooking.save();
    res.json(booking);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get user's bookings
router.get('/my-bookings', auth, async (req, res) => {
  try {
    const bookings = await Booking.find({ user: req.user.id })
      .populate('service', 'name description price');
    res.json(bookings);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;