/**
 * RatchetChat - Main Server Entry Point
 * End-to-End Encrypted Messaging Relay Server with Forward Secrecy
 *
 * Course: CS3002 Information Security (Fall 2026)
 * Student: Usman Wajid (23L-6038)
 */

require('dotenv').config();
const http = require('http');
const path = require('path');
const express = require('express');
const cors = require('cors');
const { Server } = require('socket.io');

const db = require('./database.js');
const authRoutes = require('./routes/auth.js');
const prekeyRoutes = require('./routes/prekeys.js');
const messageRoutes = require('./routes/messages.js');
const adminRoutes = require('./routes/admin.js');
const { initializeSocket } = require('./sockets/chatHandler.js');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
});

const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve Client Static Files
app.use(express.static(path.join(__dirname, '../client')));

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/prekeys', prekeyRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/admin', adminRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'RatchetChat Zero-Knowledge Relay Server',
    timestamp: new Date().toISOString(),
    database: db.getStats(),
  });
});

// Single Page Application routing fallback
app.use((req, res, next) => {
  if (req.path.startsWith('/api')) {
    return next();
  }
  res.sendFile(path.join(__dirname, '../client/index.html'));
});

// Start Server
async function startServer() {
  await db.init();
  initializeSocket(io);

  let currentPort = parseInt(process.env.PORT || 3000, 10);

  function tryListen(port) {
    const onError = (err) => {
      if (err.code === 'EADDRINUSE') {
        console.warn(`Port ${port} in use, attempting port ${port + 1}...`);
        tryListen(port + 1);
      } else {
        console.error('Fatal Server Startup Error:', err);
        process.exit(1);
      }
    };
    const onListening = () => {
      server.removeListener('error', onError);
      console.log(`=======================================================`);
      console.log(` RatchetChat Relay Server is running on port ${port}`);
      console.log(` Open Web Client: http://localhost:${port}`);
      console.log(` Status: http://localhost:${port}/api/health`);
      console.log(`=======================================================`);
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port);
  }

  tryListen(currentPort);
}

startServer().catch((err) => {
  console.error('Fatal Server Startup Error:', err);
  process.exit(1);
});

module.exports = { app, server };

