/**
 * RatchetChat - Client KeyStore Module
 * Secure persistent local storage for keys and Double Ratchet session states.
 * Private keys NEVER leave the client browser.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.RatchetKeyStore = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  class KeyStore {
    constructor(storagePrefix = 'ratchetchat_') {
      this.prefix = storagePrefix;
      this.memoryStore = new Map();
      this.hasLocalStorage = typeof window !== 'undefined' && !!window.localStorage;
    }

    _getKey(key) {
      return this.prefix + key;
    }

    set(key, value) {
      const fullKey = this._getKey(key);
      const serialized = JSON.stringify(value);
      this.memoryStore.set(fullKey, serialized);
      if (this.hasLocalStorage) {
        try {
          window.localStorage.setItem(fullKey, serialized);
        } catch (e) {
          console.warn('LocalStorage write failed, using memory store fallback:', e);
        }
      }
    }

    get(key) {
      const fullKey = this._getKey(key);
      if (this.hasLocalStorage) {
        try {
          const item = window.localStorage.getItem(fullKey);
          if (item !== null) return JSON.parse(item);
        } catch (e) {
          console.warn('LocalStorage read failed, using memory store fallback:', e);
        }
      }
      const mem = this.memoryStore.get(fullKey);
      return mem ? JSON.parse(mem) : null;
    }

    remove(key) {
      const fullKey = this._getKey(key);
      this.memoryStore.delete(fullKey);
      if (this.hasLocalStorage) {
        try {
          window.localStorage.removeItem(fullKey);
        } catch (e) {}
      }
    }

    clear() {
      this.memoryStore.clear();
      if (this.hasLocalStorage) {
        try {
          const toRemove = [];
          for (let i = 0; i < window.localStorage.length; i++) {
            const k = window.localStorage.key(i);
            if (k && k.startsWith(this.prefix)) {
              toRemove.push(k);
            }
          }
          toRemove.forEach((k) => window.localStorage.removeItem(k));
        } catch (e) {}
      }
    }
  }

  return {
    KeyStore,
  };
});

