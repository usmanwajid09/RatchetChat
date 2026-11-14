/**
 * RatchetChat - Client WebSocket Manager (Socket.io)
 */

const ChatSocket = (function () {
  let socket = null;
  const eventListeners = new Map();

  function connect(token) {
    if (socket) {
      socket.disconnect();
    }

    if (typeof io === 'undefined') {
      console.warn('Socket.io client library not loaded yet');
      return null;
    }

    socket = io({
      auth: { token },
      transports: ['websocket', 'polling'],
    });

    socket.on('connect', () => {
      console.log('[Socket] Connected to relay server with ID:', socket.id);
      trigger('connect', { socketId: socket.id });
    });

    socket.on('disconnect', (reason) => {
      console.log('[Socket] Disconnected:', reason);
      trigger('disconnect', { reason });
    });

    socket.on('receive_e2ee_message', (messageData) => {
      trigger('message', messageData);
    });

    socket.on('pending_messages_delivered', (data) => {
      trigger('pending_messages', data.messages || []);
    });

    socket.on('presence_update', (data) => {
      trigger('presence', data.onlineUsers || []);
    });

    socket.on('inspector_packet', (packet) => {
      trigger('inspector_packet', packet);
    });

    socket.on('connect_error', (err) => {
      console.error('[Socket] Connection error:', err.message);
      trigger('error', err);
    });

    return socket;
  }

  function disconnect() {
    if (socket) {
      socket.disconnect();
      socket = null;
    }
  }

  function sendMessage(recipient, payload) {
    return new Promise((resolve, reject) => {
      if (!socket || !socket.connected) {
        return reject(new Error('Socket not connected'));
      }
      socket.emit('send_e2ee_message', { recipient, payload }, (res) => {
        if (res && res.error) {
          reject(new Error(res.error));
        } else {
          resolve(res);
        }
      });
    });
  }

  function on(eventName, callback) {
    if (!eventListeners.has(eventName)) {
      eventListeners.set(eventName, []);
    }
    eventListeners.get(eventName).push(callback);
  }

  function trigger(eventName, data) {
    const list = eventListeners.get(eventName);
    if (list) {
      list.forEach((cb) => {
        try {
          cb(data);
        } catch (e) {
          console.error(`Error in socket listener for ${eventName}:`, e);
        }
      });
    }
  }

  function isConnected() {
    return socket && socket.connected;
  }

  return {
    connect,
    disconnect,
    sendMessage,
    on,
    isConnected,
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = ChatSocket;
}
