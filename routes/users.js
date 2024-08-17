const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Load environment variables
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;

// User sign-up
router.post('/signup', async (req, res) => {
    const { firstname, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        const user = new User({ firstname, email, password });
        await user.save();

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({ token, user: { firstname, email } });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// User sign-in
router.post('/signin', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ token, user: { firstname: user.firstname, email: user.email } });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Get user profile
router.get('/profile', async (req, res) => {
    
    try {
        const token = req.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({ user });
    } catch (err) {
        res.status(401).json({ message: 'Unauthorized', error: err.message });
    }
});

module.exports = router;



