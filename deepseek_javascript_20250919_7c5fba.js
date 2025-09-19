// server.js (Express API)
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Stream schema
const streamSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  thumbnail: { type: String, required: true },
  streamUrl: { type: String, required: true },
  isLive: { type: Boolean, default: false },
  tags: [String],
  category: { type: String, default: 'General' },
  createdAt: { type: Date, default: Date.now },
});

const Stream = mongoose.model('Stream', streamSchema);

// User schema for admin
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'admin' },
});

const User = mongoose.model('User', userSchema);

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};

// Routes

// Get all streams
app.get('/api/streams', async (req, res) => {
  try {
    const streams = await Stream.find();
    res.json(streams);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get single stream
app.get('/api/streams/:id', async (req, res) => {
  try {
    const stream = await Stream.findById(req.params.id);
    if (!stream) {
      return res.status(404).json({ message: 'Stream not found' });
    }
    res.json(stream);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Admin login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token, user: { id: user._id, email: user.email } });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create stream (admin only)
app.post('/api/streams', authenticateToken, async (req, res) => {
  const stream = new Stream(req.body);

  try {
    const newStream = await stream.save();
    res.status(201).json(newStream);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Update stream (admin only)
app.put('/api/streams/:id', authenticateToken, async (req, res) => {
  try {
    const stream = await Stream.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!stream) {
      return res.status(404).json({ message: 'Stream not found' });
    }
    res.json(stream);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Delete stream (admin only)
app.delete('/api/streams/:id', authenticateToken, async (req, res) => {
  try {
    const stream = await Stream.findByIdAndDelete(req.params.id);
    if (!stream) {
      return res.status(404).json({ message: 'Stream not found' });
    }
    res.json({ message: 'Stream deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});