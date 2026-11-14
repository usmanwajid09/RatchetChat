/**
 * RatchetChat - WebSocket Real-Time Message Relay
 *
 * Implements a transparent, zero-knowledge relay:
 * - Direct real-time message routing
 * - Offline message queueing fallback
 * - Broadcasts relay packet stream to Attack Lab inspector
 */

const jwt = require('jsonwebtoken');
const db = require('../database.js');
const { JWT_SECRET } = require('../middleware/authMiddleware.js');

function initializeSocket(io) {
  // Authentication middleware for Socket.io
  io.use((socket, next) => {
    const token = socket.handshake.auth.token || socket.handshake.query.token;
    if (!token) {
      return next(new Error('Authentication error: Missing token'));
    }
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.user = decoded;
      next();
    } catch (err) {
      return next(new Error('Authentication error: Invalid token'));
    }
  });

  const onlineUsers = new Map(); // username -> socketId

  io.on('connection', async (socket) => {
    const username = socket.user.username;
    onlineUsers.set(username.toLowerCase(), socket.id);
    socket.join(`user:${username.toLowerCase()}`);

    console.log(`[Socket] User connected: ${username} (${socket.id})`);
    db.addAuditLog('CLIENT_CONNECTED', { username, socketId: socket.id });

    // Broadcast presence update
    io.emit('presence_update', {
      onlineUsers: Array.from(onlineUsers.keys()),
    });

    // Check for queued offline messages
    try {
      const pendingMessages = await db.getPendingMessages(username);
      if (pendingMessages.length > 0) {
        console.log(`[Socket] Delivering ${pendingMessages.length} queued messages to ${username}`);
        socket.emit('pending_messages_delivered', {
          messages: pendingMessages,
        });
      }
    } catch (e) {
      console.error('Error delivering pending messages:', e);
    }

    // Handle real-time E2EE message relay
    socket.on('send_e2ee_message', async (data, callback) => {
      try {
        const { recipient, payload } = data;
        if (!recipient || !payload) {
          if (callback) callback({ error: 'Recipient and payload required' });
          return;
        }

        const sender = socket.user.username;
        const recipientKey = recipient.toLowerCase();
        const recipientSocketId = onlineUsers.get(recipientKey);

        const messageData = {
          id: 'msg_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6),
          sender,
          recipient,
          payload, // Zero-knowledge ciphertext and ratchet header
          timestamp: new Date().toISOString(),
        };

        // Audit log for Attack Lab packet sniffer
        db.addAuditLog('CIPHERTEXT_RELAYED', {
          id: messageData.id,
          sender,
          recipient,
          header: payload.header,
          ciphertextLength: payload.ciphertextHex ? payload.ciphertextHex.length / 2 : 0,
          timestamp: messageData.timestamp,
        });

        // Broadcast to Attack Lab listeners
        io.emit('inspector_packet', {
          id: messageData.id,
          sender,
          recipient,
          header: payload.header,
          iv: payload.ivHex,
          ciphertextPreview: payload.ciphertextHex ? payload.ciphertextHex.slice(0, 32) + '...' : '',
          timestamp: messageData.timestamp,
        });

        if (recipientSocketId) {
          // Direct real-time delivery
          io.to(`user:${recipientKey}`).emit('receive_e2ee_message', messageData);
          if (callback) callback({ status: 'delivered_realtime', messageId: messageData.id });
        } else {
          // Offline recipient: Queue in database
          await db.queueMessage(sender, recipient, payload);
          if (callback) callback({ status: 'queued_offline', messageId: messageData.id });
        }
      } catch (err) {
        console.error('Relay error:', err);
        if (callback) callback({ error: err.message });
      }
    });

    // Handle typing events
    socket.on('typing', (data) => {
      const recipientKey = data.recipient ? data.recipient.toLowerCase() : null;
      if (recipientKey) {
        io.to(`user:${recipientKey}`).emit('user_typing', {
          sender: socket.user.username,
        });
      }
    });

    socket.on('disconnect', () => {
      console.log(`[Socket] User disconnected: ${username}`);
      onlineUsers.delete(username.toLowerCase());
      db.addAuditLog('CLIENT_DISCONNECTED', { username });

      io.emit('presence_update', {
        onlineUsers: Array.from(onlineUsers.keys()),
      });
    });
  });
}

module.exports = {
  initializeSocket,
};

