// USBRemote/Server/public/app.js

// Global State
let localCertificate = null;
let localPrivateKeyPEM = null;
let localPrivateKeyObj = null; // Web Crypto key object

let isDemoMode = false;
let mode = 'select'; // 'auth', 'select', 'sender', 'receiver', 'session'
let clientId = '';
let receiverCode = '';
let peerComputerName = '';
let peerCert = null;

let pollInterval = null;
let chatMessages = [];
let logs = [];
let localStream = null;
let peerConnection = null;

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

// Helper to convert ArrayBuffer to base64
function arrayBufferToBase64(buffer) {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
  return window.btoa(binary);
}

// Helper to convert base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper to format key buffer to PEM string
function arrayBufferToPEM(buffer, label) {
  const base64 = arrayBufferToBase64(buffer);
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

// Helper to extract clean base64 string from PEM file
function pemToBase64(pemStr, label) {
  const clean = pemStr
    .replace(`-----BEGIN ${label}-----`, '')
    .replace(`-----END ${label}-----`, '')
    .replace(/\s+/g, '');
  return clean;
}

// Generate RSA-2048 key pair
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

// Sign a string challenge using private key object
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

// Verify signature using public key PEM string
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

// Import PKCS8 private key PEM to SubtleCrypto object
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

// SHA256 helper
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
    category, // 'SECURITY', 'USB', 'NET', 'SESSION'
    message
  };
  logs.push(log);
  console.log(`[${log.timestamp}] [${category}] ${message}`);

  // Update DOM if visible
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

  // Manage Nav states
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

    // Toggle unlock button
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

    // Self-sign the metadata to match the Electron cert structure
    const metaString = JSON.stringify({ id: certificate.id, owner: certificate.owner, createdAt: certificate.createdAt });
    // Import private key temporarily to sign
    const tempPrivKey = await importPrivateKey(privatePEM);
    const signature = await signChallenge(metaString, tempPrivKey);
    certificate.signature = signature;

    // Download files
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
    // Import private key to SubtleCrypto object
    localPrivateKeyObj = await importPrivateKey(loadedPrivateKeyText);
    localPrivateKeyPEM = loadedPrivateKeyText;
    localCertificate = loadedCertObj;

    // Verify keypair alignment
    const challenge = Math.random().toString(36).substring(7);
    const sig = await signChallenge(challenge, localPrivateKeyObj);
    const aligned = await verifyChallenge(challenge, sig, localCertificate.publicKey);

    if (!aligned) {
      alert('Authentication failure: Private key does not correspond to the public key in certificate.json');
      return;
    }

    addLog('SECURITY', `Identity unlocked: ${localCertificate.label} (ID: ${localCertificate.id})`);
    
    // Update UI status cards
    document.getElementById('credential-unloaded').style.display = 'none';
    document.getElementById('credential-loaded').style.display = 'flex';
    document.getElementById('cert-label').innerText = localCertificate.label;
    document.getElementById('cert-id').innerText = `ID: ${localCertificate.id.substring(0, 8)}...`;
    document.getElementById('btn-change-cert').style.display = 'inline-block';
    
    navButtons.mode.disabled = false;

    // Go to Mode select
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

// --- HTTP Polling Signaling Client ---

function getBaseUrl() {
  // Returns current host address (compatible with Vercel deployment)
  return window.location.origin;
}

// Clean connection states
function cleanupConnections() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
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

// Poll API endpoint
function startSignalingPoll() {
  if (pollInterval) clearInterval(pollInterval);
  
  pollInterval = setInterval(async () => {
    try {
      const res = await fetch(`${getBaseUrl()}/api/poll`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: clientId, role: mode })
      });
      const data = await res.json();
      
      if (data && data.type !== 'idle' && data.type !== 'waiting') {
        handleSignalingMessage(data);
      }
    } catch (err) {
      console.error('Signaling HTTP Poll crash:', err);
    }
  }, 1500);
}

// Send a WebRTC Signal
async function sendSignal(signalData) {
  try {
    await fetch(`${getBaseUrl()}/api/send-signal`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: clientId, role: mode, signal: signalData })
    });
  } catch (err) {
    console.error('Failed to dispatch signaling HTTP post:', err);
  }
}

// Message Dispatcher
async function handleSignalingMessage(msg) {
  switch (msg.type) {
    case 'incoming-request': {
      // Receiver displays Accept modal
      peerCert = msg.peerCert;
      peerComputerName = msg.peerComputerName;
      
      document.getElementById('req-peer-host').innerText = peerComputerName;
      document.getElementById('req-peer-id').innerText = peerCert.id;
      document.getElementById('incoming-request-box').style.display = 'block';
      
      // Save challenge to sign on click Accept
      incomingRequestChallenge = msg.challenge;
      setPairingState('incoming-request', 'Incoming authorization request...');
      break;
    }

    case 'auth-challenge': {
      // Sender signs challenge
      const { challenge, peerCert: pCert, peerComputerName: pName } = msg;
      peerCert = pCert;
      peerComputerName = pName;

      setPairingState('authenticating', 'Signing cryptographic challenge...');
      addLog('SECURITY', 'Signaling challenge received. Computing signature...');

      const signature = await signChallenge(challenge, localPrivateKeyObj);
      
      // Submit signature to server
      await fetch(`${getBaseUrl()}/api/submit-signature`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: clientId, role: 'sender', signature })
      });
      
      setPairingState('pairing', 'Awaiting receiver authentication...');
      break;
    }

    case 'verify-peer-signature': {
      // Both verify
      const { signature, challenge, peerCert: pCert } = msg;
      addLog('SECURITY', `Verifying signature of peer ${pCert.owner}...`);

      const verified = await verifyChallenge(challenge, signature, pCert.publicKey);
      addLog('SECURITY', `Mutual verification status: ${verified ? 'SUCCESS' : 'FAILED'}`);
      
      await fetch(`${getBaseUrl()}/api/submit-verification`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: clientId, role: mode, verified })
      });

      if (!verified) {
        alert('Authentication failed.');
        cleanupConnections();
      }
      break;
    }

    case 'active-session': {
      if (!sessionActive) {
        addLog('SECURITY', 'Mutual RSA Verification succeeded. Loading P2P WebRTC.');
        sessionActive = true;
        
        const badge = document.getElementById('connection-status');
        badge.className = 'status-badge status-connected';
        badge.querySelector('.status-text').innerText = 'CONNECTED';
        
        document.getElementById('session-peer-name').innerText = `SECURE LINK: ${peerComputerName.toUpperCase()}`;
        
        // Show viewport controls
        if (mode === 'receiver') {
          document.getElementById('btn-start-stream').style.display = 'inline-block';
        }
        
        switchScreen('screen-session');
        
        // Initialize WebRTC
        initializeWebRTC();
      }

      // Route WebRTC SDP and ICE signaling messages
      if (msg.signals && msg.signals.length > 0) {
        for (const sig of msg.signals) {
          handleWebRTCSignal(sig);
        }
      }
      break;
    }

    case 'declined':
      alert('The session request was declined by the remote device.');
      cleanupConnections();
      switchScreen('screen-mode');
      break;
  }
}

// --- Mode Selection triggers ---

// Receiver Mode Start
document.getElementById('btn-select-receiver').addEventListener('click', async () => {
  cleanupConnections();
  setPairingState('idle', 'Connecting to signaling cloud...');
  switchScreen('screen-receiver');

  try {
    const res = await fetch(`${getBaseUrl()}/api/register-receiver`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cert: localCertificate, computerName: 'Web-Receiver-Host' })
    });
    const data = await res.json();
    if (data.success) {
      clientId = data.receiverId;
      receiverCode = data.code;
      document.getElementById('display-receiver-code').innerText = data.code;
      setPairingState('idle', 'Awaiting connection request...');
      addLog('NET', `Registered Receiver on Vercel. Code: ${data.code}`);
      
      startSignalingPoll();
    } else {
      throw new Error(data.error);
    }
  } catch (err) {
    alert('Failed to register: ' + err.message);
    switchScreen('screen-mode');
  }
});

// Sender Mode Start
document.getElementById('btn-select-sender').addEventListener('click', async () => {
  cleanupConnections();
  switchScreen('screen-sender');
  setPairingState('idle', 'Connecting to signaling cloud...');

  try {
    const res = await fetch(`${getBaseUrl()}/api/register-sender`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cert: localCertificate })
    });
    const data = await res.json();
    if (data.success) {
      clientId = data.senderId;
      setPairingState('idle', 'Ready to connect.');
      addLog('NET', 'Registered Sender on Vercel.');
    } else {
      throw new Error(data.error);
    }
  } catch (err) {
    alert('Failed to register sender: ' + err.message);
    switchScreen('screen-mode');
  }
});

// Sender Connect action
document.getElementById('btn-sender-connect').addEventListener('click', async () => {
  const code = document.getElementById('input-pair-code').value.trim();
  if (code.length < 6) return;

  setPairingState('pairing', 'Initiating connection tunnel request...');
  
  try {
    const res = await fetch(`${getBaseUrl()}/api/connect-request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        senderId: clientId,
        code: code,
        cert: localCertificate,
        computerName: 'Web-Sender-Host'
      })
    });
    const data = await res.json();
    
    if (data.success) {
      handleSignalingMessage({
        type: 'auth-challenge',
        challenge: data.challenge,
        peerCert: data.peerCert,
        peerComputerName: data.peerComputerName
      });
    } else {
      throw new Error(data.error);
    }
  } catch (err) {
    alert('Pairing request failed: ' + err.message);
    setPairingState('idle');
  }
});

// Receiver Accept request
let incomingRequestChallenge = '';
document.getElementById('btn-accept-request').addEventListener('click', async () => {
  document.getElementById('incoming-request-box').style.display = 'none';
  setPairingState('authenticating', 'Signing cryptographic challenge...');

  const signature = await signChallenge(incomingRequestChallenge, localPrivateKeyObj);

  await fetch(`${getBaseUrl()}/api/incoming-request-response`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ receiverId: clientId, accept: true })
  });

  await fetch(`${getBaseUrl()}/api/submit-signature`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: clientId, role: 'receiver', signature })
  });
});

// Receiver Decline request
document.getElementById('btn-decline-request').addEventListener('click', async () => {
  document.getElementById('incoming-request-box').style.display = 'none';
  await fetch(`${getBaseUrl()}/api/incoming-request-response`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ receiverId: clientId, accept: false })
  });
  setPairingState('idle', 'Request declined. Awaiting connection request...');
});

// Close active link
document.getElementById('btn-close-session').addEventListener('click', async () => {
  await fetch(`${getBaseUrl()}/api/disconnect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: clientId, role: mode })
  });
  cleanupConnections();
  switchScreen('screen-mode');
});

// --- WebRTC Screen Sharing & SDP Exchange ---

function initializeWebRTC() {
  const configuration = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
  peerConnection = new RTCPeerConnection(configuration);

  // ICE Candidates callback
  peerConnection.onicecandidate = (event) => {
    if (event.candidate) {
      sendSignal({
        type: 'ice-candidate',
        candidate: event.candidate
      });
    }
  };

  // Remote stream viewport display
  peerConnection.ontrack = (event) => {
    addLog('SESSION', 'Remote WebRTC Video Track connected.');
    const remoteVideo = document.getElementById('remote-video');
    remoteVideo.srcObject = event.streams[0];
    remoteVideo.style.display = 'block';
    document.getElementById('video-placeholder').style.display = 'none';
  };

  // Setup DataChannel (for chat overlay sync)
  if (mode === 'sender') {
    const dataChannel = peerConnection.createDataChannel('chat');
    setupDataChannel(dataChannel);
  } else {
    peerConnection.ondatachannel = (event) => {
      setupDataChannel(event.channel);
    };
  }
}

// DataChannel binding
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

// Receiver triggers desktop screen share
document.getElementById('btn-start-stream').addEventListener('click', async () => {
  try {
    localStream = await navigator.mediaDevices.getDisplayMedia({
      video: { cursor: 'always' },
      audio: false
    });
    
    // Add stream tracks to WebRTC PC
    localStream.getTracks().forEach(track => {
      peerConnection.addTrack(track, localStream);
    });

    addLog('SESSION', 'Local desktop capture track enabled.');
    
    // Create Offer
    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);
    
    sendSignal({
      type: 'offer',
      sdp: offer
    });

    document.getElementById('btn-start-stream').style.display = 'none';
  } catch (err) {
    alert('Screen sharing failed: ' + err.message);
  }
});

// WebRTC signal receiver
async function handleWebRTCSignal(signal) {
  if (signal.type === 'offer') {
    addLog('SESSION', 'WebRTC Offer SDP received.');
    await peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp));
    
    const answer = await peerConnection.createAnswer();
    await peerConnection.setLocalDescription(answer);
    
    sendSignal({
      type: 'answer',
      sdp: answer
    });
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

  // Try data channel first, fallback to signaling poll
  if (window.activeDataChannel && window.activeDataChannel.readyState === 'open') {
    window.activeDataChannel.send(JSON.stringify({ type: 'chat', text }));
  } else {
    // Polling signal fallback
    sendSignal({ type: 'chat', text });
  }

  appendChatMessage('me', text);
  input.value = '';
});

document.getElementById('input-chat').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('btn-send-chat').click();
});

// Sync clipboard action
document.getElementById('btn-sync-clipboard').addEventListener('click', () => {
  const payload = { type: 'clipboard' };
  if (window.activeDataChannel && window.activeDataChannel.readyState === 'open') {
    window.activeDataChannel.send(JSON.stringify(payload));
  } else {
    sendSignal(payload);
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
