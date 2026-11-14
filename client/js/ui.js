/**
 * RatchetChat - UI Controller & Event Binder
 */

document.addEventListener('DOMContentLoaded', () => {
  // Navigation elements
  const navigationTabBar = document.getElementById('navigationTabBar');
  const navTabBtns = document.querySelectorAll('.nav-tab-btn');
  const chatTab = document.getElementById('chatTab');
  const attackLabTab = document.getElementById('attackLabTab');
  const inspectorTab = document.getElementById('inspectorTab');
  const authScreen = document.getElementById('authScreen');

  // Header elements
  const headerUserSection = document.getElementById('headerUserSection');
  const headerUsername = document.getElementById('headerUsername');
  const logoutBtn = document.getElementById('logoutBtn');
  const modeToggleBtn = document.getElementById('modeToggleBtn');
  const modeIcon = document.getElementById('modeIcon');
  const modeLabel = document.getElementById('modeLabel');

  // Security alert banner
  const securityAlertBanner = document.getElementById('securityAlertBanner');
  const securityAlertText = document.getElementById('securityAlertText');
  const dismissAlertBtn = document.getElementById('dismissAlertBtn');

  // Auth elements
  const authUsernameInput = document.getElementById('authUsernameInput');
  const authPasswordInput = document.getElementById('authPasswordInput');
  const authLoginBtn = document.getElementById('authLoginBtn');
  const authRegisterBtn = document.getElementById('authRegisterBtn');
  const authStatusMsg = document.getElementById('authStatusMsg');
  const quickUserBtns = document.querySelectorAll('.quick-user-btn');

  // Chat elements
  const sidebarMyUsername = document.getElementById('sidebarMyUsername');
  const myFingerprintPreview = document.getElementById('myFingerprintPreview');
  const contactsListContainer = document.getElementById('contactsListContainer');
  const refreshContactsBtn = document.getElementById('refreshContactsBtn');
  const noContactSelectedView = document.getElementById('noContactSelectedView');
  const activeChatWindow = document.getElementById('activeChatWindow');
  const activeContactName = document.getElementById('activeContactName');
  const activeContactOnlineDot = document.getElementById('activeContactOnlineDot');
  const activeContactSessionStatus = document.getElementById('activeContactSessionStatus');
  const telemetryRootKey = document.getElementById('telemetryRootKey');
  const telemetrySentCount = document.getElementById('telemetrySentCount');
  const telemetryRecvCount = document.getElementById('telemetryRecvCount');
  const messagesContainer = document.getElementById('messagesContainer');
  const sendMessageForm = document.getElementById('sendMessageForm');
  const messageTextInput = document.getElementById('messageTextInput');
  const viewSafetyNumberBtn = document.getElementById('viewSafetyNumberBtn');
  const safetyBtnLabel = document.getElementById('safetyBtnLabel');

  // Safety Number Modal
  const safetyNumberModal = document.getElementById('safetyNumberModal');
  const closeSafetyModalBtn = document.getElementById('closeSafetyModalBtn');
  const doneSafetyModalBtn = document.getElementById('doneSafetyModalBtn');
  const modalContactName = document.getElementById('modalContactName');
  const modalSafetyNumberDigits = document.getElementById('modalSafetyNumberDigits');
  const modalMitmAlertWarning = document.getElementById('modalMitmAlertWarning');
  const markVerifiedCheckbox = document.getElementById('markVerifiedCheckbox');

  // Packet Details Modal
  const packetDetailModal = document.getElementById('packetDetailModal');
  const closePacketModalBtn = document.getElementById('closePacketModalBtn');
  const packetDetailJson = document.getElementById('packetDetailJson');

  // Attack Lab elements
  const runAttack1Btn = document.getElementById('runAttack1Btn');
  const runAttack2TamperBtn = document.getElementById('runAttack2TamperBtn');
  const runAttack2ReplayBtn = document.getElementById('runAttack2ReplayBtn');
  const runAttack3Btn = document.getElementById('runAttack3Btn');
  const clearTerminalBtn = document.getElementById('clearTerminalBtn');
  const attackConsoleOutput = document.getElementById('attackConsoleOutput');
  const refreshInspectorBtn = document.getElementById('refreshInspectorBtn');

  // --- Initial Setup ---
  AttackLab.init();

  // Tab Switching
  navTabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      navTabBtns.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const target = btn.dataset.tab;

      chatTab.style.display = target === 'chatTab' ? 'flex' : 'none';
      attackLabTab.style.display = target === 'attackLabTab' ? 'block' : 'none';
      inspectorTab.style.display = target === 'inspectorTab' ? 'block' : 'none';

      if (target === 'inspectorTab') {
        AttackLab.renderLivePacketStream();
      }
    });
  });

  // Security Mode Toggle
  modeToggleBtn.addEventListener('click', () => {
    const isNowWeak = !ChatManager.isWeakMode();
    ChatManager.setWeakMode(isNowWeak);
    updateModeUI(isNowWeak);
  });

  function updateModeUI(isWeak) {
    if (isWeak) {
      modeToggleBtn.className = 'security-mode-toggle weak';
      modeIcon.innerHTML = '<i class="bi bi-shield-slash text-danger"></i>';
      modeLabel.textContent = 'Weak Mode (Vulnerable Prototype)';
    } else {
      modeToggleBtn.className = 'security-mode-toggle secure';
      modeIcon.innerHTML = '<i class="bi bi-shield-check text-success"></i>';
      modeLabel.textContent = 'Secure Mode (Signal E2EE)';
    }
  }

  // Quick 1-Click User Fill
  quickUserBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const user = btn.dataset.user;
      authUsernameInput.value = user;
      authPasswordInput.value = 'password123';
      authLoginBtn.click();
    });
  });

  // Auth Handlers
  authLoginBtn.addEventListener('click', async () => {
    const u = authUsernameInput.value.trim();
    const p = authPasswordInput.value;
    if (!u || !p) return;

    authStatusMsg.innerHTML = '<span class="text-info"><i class="bi bi-hourglass-split"></i> Logging in and loading crypto identity...</span>';

    try {
      let res;
      try {
        res = await API.login(u, p);
      } catch (err) {
        // If login failed because user doesn't exist, automatically register for seamless testing!
        console.log('User not found, registering automatically...');
        res = await API.register(u, p);
      }

      await ChatManager.initUser(res.user, res.token);
      showAppScreen();
    } catch (err) {
      authStatusMsg.innerHTML = `<span class="text-danger"><i class="bi bi-exclamation-triangle"></i> ${err.message}</span>`;
    }
  });

  authRegisterBtn.addEventListener('click', async () => {
    const u = authUsernameInput.value.trim();
    const p = authPasswordInput.value;
    if (!u || !p) return;

    authStatusMsg.innerHTML = '<span class="text-info"><i class="bi bi-hourglass-split"></i> Creating account & generating X3DH Prekeys...</span>';
    try {
      const res = await API.register(u, p);
      await ChatManager.initUser(res.user, res.token);
      showAppScreen();
    } catch (err) {
      authStatusMsg.innerHTML = `<span class="text-danger"><i class="bi bi-exclamation-triangle"></i> ${err.message}</span>`;
    }
  });

  logoutBtn.addEventListener('click', () => {
    ChatManager.logout();
    authScreen.style.display = 'flex';
    navigationTabBar.style.display = 'none';
    chatTab.style.display = 'none';
    attackLabTab.style.display = 'none';
    inspectorTab.style.display = 'none';
    headerUserSection.style.display = 'none';
    authStatusMsg.innerHTML = '';
  });

  function showAppScreen() {
    authScreen.style.display = 'none';
    navigationTabBar.style.display = 'flex';
    chatTab.style.display = 'flex';
    headerUserSection.style.display = 'flex';

    const currentUser = ChatManager.getCurrentUser();
    headerUsername.textContent = currentUser.username;
    sidebarMyUsername.textContent = currentUser.username;

    // Show identity fingerprint preview
    const keys = ChatManager.getStoredUserKeys();
    if (keys) {
      const pubHex = keys.publicBundle.identitySigningKeyHex;
      myFingerprintPreview.textContent = `${pubHex.slice(0, 16)}...${pubHex.slice(-8)}`;
    }

    renderContacts();
  }

  // Render Contacts List
  function renderContacts() {
    const contacts = ChatManager.getContacts();
    contactsListContainer.innerHTML = '';

    if (contacts.length === 0) {
      contactsListContainer.innerHTML = '<li style="padding: 16px; font-size: 0.8rem; color: var(--text-muted); text-align: center;">No other users registered yet. Open another tab as "Bob"!</li>';
      return;
    }

    const activeUser = ChatManager.getActiveContact();

    contacts.forEach((c) => {
      const li = document.createElement('li');
      li.className = `contact-item ${activeUser && activeUser.toLowerCase() === c.username.toLowerCase() ? 'active' : ''}`;
      li.innerHTML = `
        <div>
          <div style="font-weight: 600;">
            <span class="status-dot ${c.online ? 'online' : ''}"></span>
            ${c.username}
          </div>
          <small style="font-size: 0.7rem; color: var(--text-muted);">
            ${c.hasPrekeys ? 'Prekeys published' : 'Offline'}
          </small>
        </div>
        <div>
          <i class="bi bi-chevron-right" style="color: var(--text-muted); font-size: 0.8rem;"></i>
        </div>
      `;
      li.addEventListener('click', () => {
        selectContact(c.username);
      });
      contactsListContainer.appendChild(li);
    });
  }

  function selectContact(username) {
    ChatManager.setActiveContact(username);
    noContactSelectedView.style.display = 'none';
    activeChatWindow.style.display = 'flex';
    activeContactName.textContent = username;

    const contacts = ChatManager.getContacts();
    const contactObj = contacts.find((c) => c.username.toLowerCase() === username.toLowerCase());
    if (contactObj && contactObj.online) {
      activeContactOnlineDot.className = 'status-dot online';
    } else {
      activeContactOnlineDot.className = 'status-dot';
    }

    updateSafetyBtnState();
    updateTelemetry();
    renderMessages();
    renderContacts();
  }

  function updateSafetyBtnState() {
    const contact = ChatManager.getActiveContact();
    const safety = ChatManager.getSafetyNumber(contact);
    if (safety && safety.verified) {
      safetyBtnLabel.textContent = 'Verified';
      viewSafetyNumberBtn.style.color = 'var(--accent-green)';
    } else if (safety && safety.alert) {
      safetyBtnLabel.textContent = 'KEY CHANGED!';
      viewSafetyNumberBtn.style.color = 'var(--accent-red)';
    } else {
      safetyBtnLabel.textContent = 'Safety Number';
      viewSafetyNumberBtn.style.color = 'var(--text-main)';
    }
  }

  function updateTelemetry() {
    const contact = ChatManager.getActiveContact();
    const metrics = ChatManager.getSessionMetrics(contact);
    if (metrics) {
      telemetryRootKey.textContent = metrics.rootKeyHex.slice(0, 10) + '...';
      telemetrySentCount.textContent = metrics.messagesSent;
      telemetryRecvCount.textContent = metrics.messagesReceived;
    } else {
      telemetryRootKey.textContent = 'Waiting for handshake';
      telemetrySentCount.textContent = 0;
      telemetryRecvCount.textContent = 0;
    }
  }

  // Render Messages
  function renderMessages() {
    const contact = ChatManager.getActiveContact();
    if (!contact) return;

    const messages = ChatManager.getChatHistory(contact);
    messagesContainer.innerHTML = '';

    messages.forEach((msg) => {
      const bubble = document.createElement('div');
      const isError = msg.error || msg.status === 'FAILED';
      bubble.className = `message-bubble ${msg.isOutgoing ? 'out' : 'in'} ${isError ? 'error' : ''}`;

      bubble.innerHTML = `
        <div class="message-text">${escapeHtml(msg.text)}</div>
        <div class="message-meta">
          <span>${new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          <i class="bi bi-info-circle" title="Click to view raw cryptographic packet"></i>
        </div>
      `;

      // Clicking message bubble displays raw cryptographic details modal
      bubble.addEventListener('click', () => {
        showPacketDetails(msg);
      });

      messagesContainer.appendChild(bubble);
    });

    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  function showPacketDetails(msg) {
    packetDetailJson.textContent = JSON.stringify(msg, null, 2);
    packetDetailModal.style.display = 'flex';
  }

  closePacketModalBtn.addEventListener('click', () => {
    packetDetailModal.style.display = 'none';
  });

  // Sending Message
  sendMessageForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = messageTextInput.value.trim();
    const contact = ChatManager.getActiveContact();
    if (!text || !contact) return;

    messageTextInput.value = '';
    try {
      await ChatManager.sendMessage(contact, text);
    } catch (err) {
      alert(`Send Error: ${err.message}`);
    }
  });

  // Safety Number Modal Handlers
  viewSafetyNumberBtn.addEventListener('click', async () => {
    const contact = ChatManager.getActiveContact();
    if (!contact) return;

    modalContactName.textContent = contact;
    let safety = ChatManager.getSafetyNumber(contact);

    if (!safety) {
      // Calculate on the fly if needed
      try {
        const bundleRes = await API.fetchPrekeyBundle(contact);
        const myKeys = ChatManager.getStoredUserKeys();
        safety = await RatchetSafetyNumber.computeSafetyNumber(
          myKeys.identityKeys.signing.publicKey,
          bundleRes.bundle.identitySigningKeyHex
        );
        ChatManager.verifySafetyNumber(contact, false);
      } catch (e) {
        modalSafetyNumberDigits.textContent = 'Could not load safety number: ' + e.message;
        safetyNumberModal.style.display = 'flex';
        return;
      }
    }

    modalSafetyNumberDigits.innerHTML = safety.formatted.replace('\n', '<br>');
    markVerifiedCheckbox.checked = !!safety.verified;

    if (safety.alert || safety.isMitMInjected) {
      modalMitmAlertWarning.style.display = 'block';
    } else {
      modalMitmAlertWarning.style.display = 'none';
    }

    safetyNumberModal.style.display = 'flex';
  });

  closeSafetyModalBtn.addEventListener('click', () => {
    safetyNumberModal.style.display = 'none';
  });

  doneSafetyModalBtn.addEventListener('click', () => {
    const contact = ChatManager.getActiveContact();
    if (contact) {
      ChatManager.verifySafetyNumber(contact, markVerifiedCheckbox.checked);
      updateSafetyBtnState();
    }
    safetyNumberModal.style.display = 'none';
  });

  dismissAlertBtn.addEventListener('click', () => {
    securityAlertBanner.style.display = 'none';
  });

  refreshContactsBtn.addEventListener('click', () => {
    ChatManager.refreshContacts();
  });

  refreshInspectorBtn.addEventListener('click', () => {
    AttackLab.renderLivePacketStream();
  });

  // Attack Lab Event Handlers
  runAttack1Btn.addEventListener('click', async () => {
    attackConsoleOutput.textContent = 'Executing Passive Sniffing Attack...\n';
    const result = await AttackLab.runPassiveSniffingAttack();
    attackConsoleOutput.textContent = result;
  });

  runAttack2TamperBtn.addEventListener('click', async () => {
    const contact = ChatManager.getActiveContact();
    if (!contact) {
      attackConsoleOutput.textContent = 'Please select a contact in the Chat tab first to intercept their message!';
      return;
    }
    attackConsoleOutput.textContent = 'Injecting Ciphertext Bit-Flip Tamper Attack...\n';
    const result = await AttackLab.runTamperAttack(contact, 0);
    attackConsoleOutput.textContent = result;
  });

  runAttack2ReplayBtn.addEventListener('click', async () => {
    const contact = ChatManager.getActiveContact();
    if (!contact) {
      attackConsoleOutput.textContent = 'Please select a contact in the Chat tab first!';
      return;
    }
    attackConsoleOutput.textContent = 'Executing Packet Replay Attack...\n';
    const result = await AttackLab.runReplayAttack(contact);
    attackConsoleOutput.textContent = result;
  });

  runAttack3Btn.addEventListener('click', async () => {
    const me = ChatManager.getCurrentUser() ? ChatManager.getCurrentUser().username : 'Alice';
    const contact = ChatManager.getActiveContact() || 'Bob';
    attackConsoleOutput.textContent = `Executing MitM Key Substitution Attack (${ChatManager.isWeakMode() ? 'Weak Mode' : 'Secure Mode'})...\n`;
    const result = await AttackLab.runMitmSimulation(me, contact, ChatManager.isWeakMode());
    attackConsoleOutput.textContent = result;
  });

  clearTerminalBtn.addEventListener('click', () => {
    attackConsoleOutput.textContent = 'Terminal cleared. Select an attack to run.';
  });

  // State Change & Message Listeners
  ChatManager.onStateChange(() => {
    renderContacts();
    updateTelemetry();
    updateSafetyBtnState();

    // Check if any contact has security alert
    const activeC = ChatManager.getActiveContact();
    const safety = ChatManager.getSafetyNumber(activeC);
    if (safety && safety.alert) {
      securityAlertBanner.style.display = 'flex';
      securityAlertText.textContent = `SECURITY ALERT: ${activeC}'s Identity Key has changed! Possible Man-in-the-Middle attack in progress!`;
    }
  });

  ChatManager.onMessage(() => {
    renderMessages();
    updateTelemetry();
  });

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
});
