// routes/services.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Service = require('../models/Services');

// Get all active services
router.get('/', async (req, res) => {
  try {
    const services = await Service.find({ isActive: true });
    res.json(services);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get service by ID
router.get('/:id', async (req, res) => {
  try {
    const service = await Service.findById(req.params.id);
    if (!service) {
      return res.status(404).json({ msg: 'Service not found' });
    }
    res.json(service);
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ msg: 'Service not found' });
    }
    res.status(500).send('Server error');
  }
});

// Admin routes for service management
router.post('/', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ msg: 'Unauthorized' });
    }

    const { name, description, category, price, duration, preparationInstructions } = req.body;
    
    const newService = new Service({
      name,
      description,
      category,
      price,
      duration,
      preparationInstructions
    });

    const service = await newService.save();
    res.json(service);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;