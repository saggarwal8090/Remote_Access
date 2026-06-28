// USBRemote/Server/public/app.js

// Global State
let localCertificate = null;
let localPrivateKeyPEM = null;
let localPrivateKeyObj = null; // Web Crypto key object

let mode = 'select'; // 'auth', 'select', 'sender', 'receiver', 'session'
let clientId = '';
let receiverCode = '';
let peerComputerName = '';
let peerCert = null;

let socket = null;
let chatMessages = [];
let logs = [];
let localStream = null;
let peerConnection = null;
let sessionActive = false;

// DOM Elements
const screens = {
  auth: document.getElementById('screen-auth'),
  mode: document.getElementById('screen-mode'),
  sender: document.getElementById('screen-sender'),
  receiver: document.getElementById('screen-receiver'),
  session: document.getElementById('screen-session'),
  logs: document.getElementById('screen-logs')
};

const navButtons = {
  mode: document.getElementById('nav-mode'),
  logs: document.getElementById('nav-logs')
};

// --- Web Crypto Helpers ---

function arrayBufferToBase64(buffer) {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function arrayBufferToPEM(buffer, label) {
  const base64 = arrayBufferToBase64(buffer);
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

function pemToBase64(pemStr, label) {
  return pemStr
    .replace(`-----BEGIN ${label}-----`, '')
    .replace(`-----END ${label}-----`, '')
    .replace(/\s+/g, '');
}

async function generateRSAKeyPair() {
  return window.crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: 'SHA-256' }
    },
    true,
    ['sign', 'verify']
  );
}

async function signChallenge(challengeText, cryptoPrivateKey) {
  const encoder = new TextEncoder();
  const data = encoder.encode(challengeText);
  const sigBuffer = await window.crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    cryptoPrivateKey,
    data
  );
  return arrayBufferToBase64(sigBuffer);
}

async function verifyChallenge(challengeText, signatureBase64, publicKeyPEM) {
  try {
    const pubBase64 = pemToBase64(publicKeyPEM, 'PUBLIC KEY');
    const pubBuffer = base64ToArrayBuffer(pubBase64);
    
    const cryptoPublicKey = await window.crypto.subtle.importKey(
      'spki',
      pubBuffer,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' }
      },
      false,
      ['verify']
    );

    const encoder = new TextEncoder();
    const data = encoder.encode(challengeText);
    const sigBuffer = base64ToArrayBuffer(signatureBase64);

    return await window.crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      cryptoPublicKey,
      sigBuffer,
      data
    );
  } catch (err) {
    console.error('Signature verify failed:', err);
    return false;
  }
}

async function importPrivateKey(pemStr) {
  const cleanBase64 = pemToBase64(pemStr, 'PRIVATE KEY');
  const buffer = base64ToArrayBuffer(cleanBase64);
  return window.crypto.subtle.importKey(
    'pkcs8',
    buffer,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' }
    },
    false,
    ['sign']
  );
}

async function sha256(text) {
  const msgUint8 = new TextEncoder().encode(text);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- App Logging ---
function addLog(category, message) {
  const log = {
    timestamp: new Date().toISOString(),
    category,
    message
  };
  logs.push(log);
  console.log(`[${log.timestamp}] [${category}] ${message}`);

  const logsContainer = document.getElementById('web-logs-container');
  if (logsContainer) {
    const line = document.createElement('div');
    line.className = 'log-line';
    line.innerHTML = `
      <span class="log-time">${new Date(log.timestamp).toLocaleTimeString()}</span>
      <span class="log-cat log-${category}">[${category}]</span>
      <span class="log-msg">${message}</span>
    `;
    logsContainer.appendChild(line);
    logsContainer.scrollTop = logsContainer.scrollHeight;
  }
}

// --- DOM Navigation ---
function switchScreen(screenName) {
  Object.keys(screens).forEach(key => {
    if (key === screenName) {
      screens[key].classList.add('screen-active');
    } else {
      screens[key].classList.remove('screen-active');
    }
  });

  if (screenName === 'logs') {
    navButtons.logs.classList.add('active-nav');
    navButtons.mode.classList.remove('active-nav');
  } else {
    navButtons.logs.classList.remove('active-nav');
    navButtons.mode.classList.add('active-nav');
  }
}

// --- Drag & Drop Credential File Parsing ---
let loadedCertObj = null;
let loadedPrivateKeyText = null;

function setupDragAndDrop() {
  const setupZone = (zoneId, inputId, filenameId, type) => {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    const badge = document.getElementById(filenameId);

    zone.addEventListener('click', () => input.click());
    zone.addEventListener('dragover', (e) => {
      e.preventDefault();
      zone.classList.add('dragover');
    });
    zone.addEventListener('dragleave', () => {
      zone.classList.remove('dragover');
    });
    zone.addEventListener('drop', (e) => {
      e.preventDefault();
      zone.classList.remove('dragover');
      if (e.dataTransfer.files.length > 0) {
        handleFile(e.dataTransfer.files[0], zone, badge, type);
      }
    });
    input.addEventListener('change', () => {
      if (input.files.length > 0) {
        handleFile(input.files[0], zone, badge, type);
      }
    });
  };

  setupZone('drop-zone-cert', 'input-cert', 'cert-filename', 'cert');
  setupZone('drop-zone-key', 'input-key', 'key-filename', 'key');
}

function handleFile(file, zone, badge, type) {
  const reader = new FileReader();
  reader.onload = async (e) => {
    const text = e.target.result;
    if (type === 'cert') {
      try {
        loadedCertObj = JSON.parse(text);
        badge.innerText = file.name;
        badge.style.display = 'inline-block';
        addLog('USB', `Loaded certificate profile for ${loadedCertObj.owner}`);
      } catch (err) {
        alert('Invalid certificate.json file');
      }
    } else {
      if (text.includes('BEGIN PRIVATE KEY')) {
        loadedPrivateKeyText = text;
        badge.innerText = file.name;
        badge.style.display = 'inline-block';
        addLog('USB', 'Loaded RSA Private Key PEM file');
      } else {
        alert('Invalid private key. Must be a PEM private key.');
      }
    }

    const btnUnlock = document.getElementById('btn-authenticate');
    btnUnlock.disabled = !(loadedCertObj && loadedPrivateKeyText);
  };
  reader.readAsText(file);
}

// Generate new key Pair download
document.getElementById('btn-generate-key').addEventListener('click', async () => {
  const labelInput = document.getElementById('new-key-label');
  const label = labelInput.value.trim() || 'Browser Console Key';

  addLog('SECURITY', `Generating new RSA-2048 credential pair: "${label}"`);
  try {
    const keys = await generateRSAKeyPair();
    const pubBuffer = await window.crypto.subtle.exportKey('spki', keys.publicKey);
    const privBuffer = await window.crypto.subtle.exportKey('pkcs8', keys.privateKey);

    const publicPEM = arrayBufferToPEM(pubBuffer, 'PUBLIC KEY');
    const privatePEM = arrayBufferToPEM(privBuffer, 'PRIVATE KEY');

    const certId = (await sha256(publicPEM)).substring(0, 16);
    const certificate = {
      id: certId,
      label: label,
      owner: 'Web-Browser-Client',
      createdAt: new Date().toISOString(),
      publicKey: publicPEM
    };

    const metaString = JSON.stringify({ id: certificate.id, owner: certificate.owner, createdAt: certificate.createdAt });
    const tempPrivKey = await importPrivateKey(privatePEM);
    const signature = await signChallenge(metaString, tempPrivKey);
    certificate.signature = signature;

    downloadFile(JSON.stringify(certificate, null, 2), 'certificate.json');
    downloadFile(privatePEM, 'key.pem');

    addLog('USB', `Key registration succeeded. Downloaded certificate.json and key.pem.`);
  } catch (err) {
    console.error(err);
    alert('Failed to generate keypair: ' + err.message);
  }
});

function downloadFile(content, filename) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

// Unlock with uploaded keys
document.getElementById('btn-authenticate').addEventListener('click', async () => {
  if (!loadedCertObj || !loadedPrivateKeyText) return;

  try {
    localPrivateKeyObj = await importPrivateKey(loadedPrivateKeyText);
    localPrivateKeyPEM = loadedPrivateKeyText;
    localCertificate = loadedCertObj;

    const challenge = Math.random().toString(36).substring(7);
    const sig = await signChallenge(challenge, localPrivateKeyObj);
    const aligned = await verifyChallenge(challenge, sig, localCertificate.publicKey);

    if (!aligned) {
      alert('Authentication failure: Private key does not correspond to certificate.json');
      return;
    }

    addLog('SECURITY', `Identity unlocked: ${localCertificate.label} (ID: ${localCertificate.id})`);
    
    document.getElementById('credential-unloaded').style.display = 'none';
    document.getElementById('credential-loaded').style.display = 'flex';
    document.getElementById('cert-label').innerText = localCertificate.label;
    document.getElementById('cert-id').innerText = `ID: ${localCertificate.id.substring(0, 8)}...`;
    document.getElementById('btn-change-cert').style.display = 'inline-block';
    
    navButtons.mode.disabled = false;
    switchScreen('screen-mode');
  } catch (err) {
    console.error(err);
    alert('Credential loading crash: ' + err.message);
  }
});

// Eject certs
document.getElementById('btn-change-cert').addEventListener('click', () => {
  cleanupConnections();
  localCertificate = null;
  localPrivateKeyObj = null;
  localPrivateKeyPEM = null;
  loadedCertObj = null;
  loadedPrivateKeyText = null;

  document.getElementById('credential-unloaded').style.display = 'flex';
  document.getElementById('credential-loaded').style.display = 'none';
  document.getElementById('btn-change-cert').style.display = 'none';
  
  document.getElementById('cert-filename').style.display = 'none';
  document.getElementById('key-filename').style.display = 'none';
  document.getElementById('btn-authenticate').disabled = true;

  navButtons.mode.disabled = true;
  switchScreen('screen-auth');
});

// --- WebSocket Signaling Relay Setup ---

function getWsUrl() {
  // Automatically detects Render's WS or WSS schemes based on the host
  const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
  return protocol + window.location.host;
}

function cleanupConnections() {
  if (socket) {
    socket.close();
    socket = null;
  }
  if (peerConnection) {
    peerConnection.close();
    peerConnection = null;
  }
  if (localStream) {
    localStream.getTracks().forEach(track => track.stop());
    localStream = null;
  }

  const badge = document.getElementById('connection-status');
  badge.className = 'status-badge status-disconnected';
  badge.querySelector('.status-text').innerText = 'DISCONNECTED';

  setPairingState('idle', 'Disconnected.');
  sessionActive = false;
  document.getElementById('remote-video').style.display = 'none';
  document.getElementById('video-placeholder').style.display = 'block';
  document.getElementById('btn-start-stream').style.display = 'none';
}

function setPairingState(state, message = '') {
  const senderStatus = document.getElementById('sender-pairing-status');
  const receiverStatus = document.getElementById('receiver-pairing-status');
  
  if (state === 'authenticating' || state === 'pairing') {
    if (screens.sender.classList.contains('screen-active')) {
      document.getElementById('sender-setup-form').style.display = 'none';
      senderStatus.style.display = 'block';
      document.getElementById('sender-pairing-title').innerText = state.toUpperCase();
      document.getElementById('sender-pairing-desc').innerText = message;
    }
  } else {
    document.getElementById('sender-setup-form').style.display = 'block';
    senderStatus.style.display = 'none';
  }

  if (screens.receiver.classList.contains('screen-active')) {
    document.getElementById('receiver-pairing-desc').innerText = message;
  }
}

// Start WebSocket connection
function connectSignalingServer(selectedRole) {
  cleanupConnections();
  setPairingState('idle', 'Connecting to signaling cloud...');

  const wsUrl = getWsUrl();
  addLog('NET', `Opening socket tunnel to: ${wsUrl}`);

  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    const badge = document.getElementById('connection-status');
    badge.className = 'status-badge status-connected';
    badge.querySelector('.status-text').innerText = 'CONNECTED';
    
    addLog('NET', 'Signaling connection established.');
    setPairingState('idle', 'Registering credential signatures...');

    // Register
    socket.send(JSON.stringify({
      type: selectedRole === 'receiver' ? 'register-receiver' : 'register-sender',
      cert: localCertificate,
      computerName: 'Web-' + selectedRole.toUpperCase()
    }));
  };

  socket.onmessage = async (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch (e) {
      return;
    }
    handleSignalingMessage(msg);
  };

  socket.onerror = (err) => {
    console.error('Socket error:', err);
    addLog('NET', 'Signaling server socket error.');
  };

  socket.onclose = () => {
    addLog('NET', 'Signaling connection closed.');
    cleanupConnections();
  };
}

async function handleSignalingMessage(msg) {
  switch (msg.type) {
    case 'registered':
      receiverCode = msg.code;
      document.getElementById('display-receiver-code').innerText = msg.code;
      setPairingState('idle', 'Awaiting connection request...');
      addLog('NET', `Receiver registered. Secure Code: ${msg.code}`);
      break;

    case 'sender-registered':
      setPairingState('idle', 'Ready to connect.');
      addLog('NET', 'Sender registered.');
      break;

    case 'incoming-request': {
      const { challenge, peerCert: pCert, peerComputerName: pName } = msg;
      peerCert = pCert;
      peerComputerName = pName;
      
      document.getElementById('req-peer-host').innerText = peerComputerName;
      document.getElementById('req-peer-id').innerText = peerCert.id;
      document.getElementById('incoming-request-box').style.display = 'block';
      
      incomingRequestChallenge = challenge;
      setPairingState('incoming-request', 'Incoming authorization request...');
      break;
    }

    case 'auth-challenge': {
      const { challenge, peerCert: pCert, peerComputerName: pName } = msg;
      peerCert = pCert;
      peerComputerName = pName;

      setPairingState('authenticating', 'Signing verification challenge...');
      addLog('SECURITY', 'Signaling challenge received. Computing signature...');

      const signature = await signChallenge(challenge, localPrivateKeyObj);
      
      socket.send(JSON.stringify({
        type: 'auth-signature',
        signature: signature
      }));
      
      setPairingState('pairing', 'Awaiting receiver authentication verification...');
      break;
    }

    case 'verify-peer-signature': {
      const { signature, challenge, peerCert: pCert } = msg;
      addLog('SECURITY', `Verifying signature of peer ${pCert.owner}...`);

      const verified = await verifyChallenge(challenge, signature, pCert.publicKey);
      addLog('SECURITY', `Mutual verification status: ${verified ? 'SUCCESS' : 'FAILED'}`);
      
      socket.send(JSON.stringify({
        type: 'verify-peer-result',
        verified: verified
      }));

      if (verified) {
        peerCert = pCert;
        peerComputerName = pCert.owner;
      } else {
        alert('Authentication signature check failed.');
        cleanupConnections();
      }
      break;
    }

    case 'auth-success': {
      if (!sessionActive) {
        addLog('SECURITY', 'Mutual RSA Verification succeeded. Loading WebRTC.');
        sessionActive = true;
        
        document.getElementById('session-peer-name').innerText = `SECURE LINK: ${peerComputerName.toUpperCase()}`;
        
        if (mode === 'receiver') {
          document.getElementById('btn-start-stream').style.display = 'inline-block';
        }
        
        switchScreen('screen-session');
        initializeWebRTC();
      }
      break;
    }

    case 'connection-declined':
      alert('The session request was declined by the receiver.');
      cleanupConnections();
      switchScreen('screen-mode');
      break;

    case 'error':
      alert('Server error: ' + msg.message);
      cleanupConnections();
      switchScreen('screen-mode');
      break;

    case 'peer-disconnected':
      addLog('NET', `Remote peer disconnected: ${msg.message}`);
      cleanupConnections();
      switchScreen('screen-mode');
      break;

    case 'signal':
      handleWebRTCSignal(msg.signal);
      break;
  }
}

// --- Mode Selection triggers ---

document.getElementById('btn-select-receiver').addEventListener('click', () => {
  mode = 'receiver';
  switchScreen('screen-receiver');
  connectSignalingServer('receiver');
});

document.getElementById('btn-select-sender').addEventListener('click', () => {
  mode = 'sender';
  switchScreen('screen-sender');
  connectSignalingServer('sender');
});

// Sender Connect action
document.getElementById('btn-sender-connect').addEventListener('click', () => {
  const code = document.getElementById('input-pair-code').value.trim();
  if (code.length < 6 || !socket) return;

  setPairingState('pairing', 'Initiating connection tunnel request...');
  socket.send(JSON.stringify({
    type: 'connect-request',
    code: code
  }));
});

// Receiver Accept request
let incomingRequestChallenge = '';
document.getElementById('btn-accept-request').addEventListener('click', async () => {
  document.getElementById('incoming-request-box').style.display = 'none';
  setPairingState('authenticating', 'Signing cryptographic challenge...');

  const signature = await signChallenge(incomingRequestChallenge, localPrivateKeyObj);

  socket.send(JSON.stringify({
    type: 'incoming-request-response',
    accept: true
  }));

  socket.send(JSON.stringify({
    type: 'auth-signature',
    signature: signature
  }));
});

// Receiver Decline request
document.getElementById('btn-decline-request').addEventListener('click', () => {
  document.getElementById('incoming-request-box').style.display = 'none';
  socket.send(JSON.stringify({
    type: 'incoming-request-response',
    accept: false
  }));
  setPairingState('idle', 'Awaiting connection request...');
});

// Close session
document.getElementById('btn-close-session').addEventListener('click', () => {
  if (socket) {
    socket.send(JSON.stringify({ type: 'disconnect-peer' }));
  }
  cleanupConnections();
  switchScreen('screen-mode');
});

// --- WebRTC Screen Sharing & SDP Exchange ---

function initializeWebRTC() {
  const configuration = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
  peerConnection = new RTCPeerConnection(configuration);

  peerConnection.onicecandidate = (event) => {
    if (event.candidate) {
      socket.send(JSON.stringify({
        type: 'signal',
        signal: {
          type: 'ice-candidate',
          candidate: event.candidate
        }
      }));
    }
  };

  peerConnection.ontrack = (event) => {
    addLog('SESSION', 'Remote WebRTC Video Track connected.');
    const remoteVideo = document.getElementById('remote-video');
    remoteVideo.srcObject = event.streams[0];
    remoteVideo.style.display = 'block';
    document.getElementById('video-placeholder').style.display = 'none';
  };

  if (mode === 'sender') {
    const dataChannel = peerConnection.createDataChannel('chat');
    setupDataChannel(dataChannel);
  } else {
    peerConnection.ondatachannel = (event) => {
      setupDataChannel(event.channel);
    };
  }
}

function setupDataChannel(channel) {
  channel.onopen = () => addLog('SESSION', 'WebRTC Data Channel established.');
  channel.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'chat') {
      appendChatMessage('peer', data.text);
    } else if (data.type === 'clipboard') {
      addLog('SESSION', 'Clipboard Sync payload received.');
    }
  };
  window.activeDataChannel = channel;
}

// Start Capture Screen (Receiver)
document.getElementById('btn-start-stream').addEventListener('click', async () => {
  try {
    localStream = await navigator.mediaDevices.getDisplayMedia({
      video: { cursor: 'always' },
      audio: false
    });
    
    localStream.getTracks().forEach(track => {
      peerConnection.addTrack(track, localStream);
    });

    addLog('SESSION', 'Local screen capture active.');
    
    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);
    
    socket.send(JSON.stringify({
      type: 'signal',
      signal: {
        type: 'offer',
        sdp: offer
      }
    }));

    document.getElementById('btn-start-stream').style.display = 'none';
  } catch (err) {
    alert('Screen sharing failed: ' + err.message);
  }
});

// Route ICE / SDP signals
async function handleWebRTCSignal(signal) {
  if (signal.type === 'offer') {
    addLog('SESSION', 'WebRTC Offer SDP received.');
    await peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp));
    
    const answer = await peerConnection.createAnswer();
    await peerConnection.setLocalDescription(answer);
    
    socket.send(JSON.stringify({
      type: 'signal',
      signal: {
        type: 'answer',
        sdp: answer
      }
    }));
  } else if (signal.type === 'answer') {
    addLog('SESSION', 'WebRTC Answer SDP received.');
    await peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp));
  } else if (signal.type === 'ice-candidate') {
    try {
      await peerConnection.addIceCandidate(new RTCIceCandidate(signal.candidate));
    } catch (e) {
      console.error('Failed to append ICE Candidate:', e);
    }
  }
}

// --- Chat Actions ---

function appendChatMessage(sender, text) {
  const messagesList = document.getElementById('chat-messages');
  const bubble = document.createElement('div');
  bubble.className = `msg-bubble msg-${sender}`;
  bubble.innerHTML = `
    <p>${escapeHTML(text)}</p>
    <span class="msg-time">${new Date().toLocaleTimeString()}</span>
  `;
  messagesList.appendChild(bubble);
  messagesList.scrollTop = messagesList.scrollHeight;
}

function escapeHTML(str) {
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}

document.getElementById('btn-send-chat').addEventListener('click', () => {
  const input = document.getElementById('input-chat');
  const text = input.value.trim();
  if (!text) return;

  if (window.activeDataChannel && window.activeDataChannel.readyState === 'open') {
    window.activeDataChannel.send(JSON.stringify({ type: 'chat', text }));
  } else {
    // Fallback through WebSocket signaling
    if (socket) {
      socket.send(JSON.stringify({
        type: 'signal',
        signal: { type: 'chat', text }
      }));
    }
  }

  appendChatMessage('me', text);
  input.value = '';
});

document.getElementById('input-chat').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('btn-send-chat').click();
});

document.getElementById('btn-sync-clipboard').addEventListener('click', () => {
  const payload = { type: 'clipboard' };
  if (window.activeDataChannel && window.activeDataChannel.readyState === 'open') {
    window.activeDataChannel.send(JSON.stringify(payload));
  } else {
    if (socket) {
      socket.send(JSON.stringify({
        type: 'signal',
        signal: payload
      }));
    }
  }
  addLog('SESSION', 'Clipboard Sync signal pushed.');
});

// Logs tab binding
navButtons.logs.addEventListener('click', () => {
  switchScreen('screen-logs');
});

navButtons.mode.addEventListener('click', () => {
  if (sessionActive) switchScreen('screen-session');
  else if (mode === 'receiver') switchScreen('screen-receiver');
  else if (mode === 'sender') switchScreen('screen-sender');
  else if (localCertificate) switchScreen('screen-mode');
  else switchScreen('screen-auth');
});

document.getElementById('btn-clear-logs').addEventListener('click', () => {
  logs = [];
  document.getElementById('web-logs-container').innerHTML = '';
  addLog('SECURITY', 'Logs cleared.');
});

// Boot app
setupDragAndDrop();
addLog('SECURITY', 'USB Remote Web Console initialized.');
switchScreen('screen-auth');
