// USBRemote/Server/server.js
const { WebSocketServer } = require('ws');
const http = require('http');
const crypto = require('crypto');

// Helper to generate a random 6-digit code
function generateSessionCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('USB Remote Connect Signaling Server is running.');
});

const wss = new WebSocketServer({ server });

// Active connections
const receivers = new Map(); // sessionCode -> socket
const sockets = new Map();   // socketId -> socket details (role, cert, peerSocketId, code, etc.)

// Demo auto-pairing waitlist
let waitingDemoReceiverId = null;
let waitingDemoSenderId = null;

// Trigger challenge handshake between two sockets
function initiateHandshake(senderId, receiverId) {
  const senderInfo = sockets.get(senderId);
  const receiverInfo = sockets.get(receiverId);

  if (!senderInfo || !receiverInfo) return;

  senderInfo.peerId = receiverId;
  receiverInfo.peerId = senderId;

  // Generate security challenges for mutual authentication
  const challengeForSender = crypto.randomBytes(32).toString('hex');
  const challengeForReceiver = crypto.randomBytes(32).toString('hex');

  senderInfo.challenges.sent = challengeForSender;
  receiverInfo.challenges.sent = challengeForReceiver;

  // Send challenges to both parties
  senderInfo.ws.send(JSON.stringify({
    type: 'auth-challenge',
    challenge: challengeForSender,
    peerCert: receiverInfo.cert,
    peerComputerName: receiverInfo.computerName
  }));

  receiverInfo.ws.send(JSON.stringify({
    type: 'incoming-request',
    challenge: challengeForReceiver,
    peerCert: senderInfo.cert,
    peerComputerName: senderInfo.computerName,
    isDemo: true // flag to tell receiver it is an automated demo
  }));

  console.log(`[Server] Automated demo handshake initiated between Sender ${senderId} and Receiver ${receiverId}.`);
}

wss.on('connection', (ws) => {
  const socketId = crypto.randomUUID();
  console.log(`[Server] New socket connected: ${socketId}`);

  ws.id = socketId;
  sockets.set(socketId, {
    ws,
    id: socketId,
    role: null,
    cert: null,
    code: null,
    peerId: null,
    challenges: {} // challengeSent, signatureReceived, verified
  });

  ws.on('message', (messageStr) => {
    let msg;
    try {
      msg = JSON.parse(messageStr);
    } catch (e) {
      console.error('[Server] Failed to parse JSON message:', messageStr);
      return;
    }

    const clientInfo = sockets.get(socketId);
    if (!clientInfo) return;

    console.log(`[Server] Received type: ${msg.type} from ${socketId}`);

    switch (msg.type) {
      case 'register-receiver': {
        // Register client as receiver
        clientInfo.role = 'receiver';
        clientInfo.cert = msg.cert; // USB certificate info
        clientInfo.computerName = msg.computerName || 'Unknown-PC';

        // Generate a unique 6-digit code
        let code = generateSessionCode();
        while (receivers.has(code)) {
          code = generateSessionCode();
        }

        clientInfo.code = code;
        receivers.set(code, socketId);

        ws.send(JSON.stringify({
          type: 'registered',
          code: code
        }));
        console.log(`[Server] Receiver registered with code ${code} (${clientInfo.computerName})`);
        break;
      }

      case 'register-sender': {
        // Register client as sender
        clientInfo.role = 'sender';
        clientInfo.cert = msg.cert;
        clientInfo.computerName = msg.computerName || 'Unknown-PC';

        ws.send(JSON.stringify({
          type: 'sender-registered'
        }));
        console.log(`[Server] Sender registered: ${socketId} (${clientInfo.computerName})`);
        break;
      }

      case 'register-demo-receiver': {
        clientInfo.role = 'receiver';
        clientInfo.cert = msg.cert;
        clientInfo.computerName = msg.computerName || 'Unknown-PC';
        clientInfo.isDemo = true;

        // Generate a code just in case they want to view it
        clientInfo.code = generateSessionCode();
        receivers.set(clientInfo.code, socketId);

        ws.send(JSON.stringify({
          type: 'registered',
          code: clientInfo.code
        }));

        console.log(`[Server] Registered Demo Receiver: ${socketId}`);

        // Check if a demo sender is waiting
        if (waitingDemoSenderId && sockets.has(waitingDemoSenderId)) {
          const senderId = waitingDemoSenderId;
          waitingDemoSenderId = null;
          initiateHandshake(senderId, socketId);
        } else {
          waitingDemoReceiverId = socketId;
          console.log(`[Server] Demo Receiver placed on waitlist.`);
        }
        break;
      }

      case 'register-demo-sender': {
        clientInfo.role = 'sender';
        clientInfo.cert = msg.cert;
        clientInfo.computerName = msg.computerName || 'Unknown-PC';
        clientInfo.isDemo = true;

        ws.send(JSON.stringify({
          type: 'sender-registered'
        }));

        console.log(`[Server] Registered Demo Sender: ${socketId}`);

        // Check if a demo receiver is waiting
        if (waitingDemoReceiverId && sockets.has(waitingDemoReceiverId)) {
          const receiverId = waitingDemoReceiverId;
          waitingDemoReceiverId = null;
          initiateHandshake(socketId, receiverId);
        } else {
          waitingDemoSenderId = socketId;
          console.log(`[Server] Demo Sender placed on waitlist.`);
        }
        break;
      }

      case 'connect-request': {
        const { code } = msg;
        console.log(`[Server] Connection request from Sender ${socketId} for code ${code}`);

        const targetReceiverId = receivers.get(code);
        if (!targetReceiverId) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Receiver ID not found or offline.'
          }));
          return;
        }

        const receiverInfo = sockets.get(targetReceiverId);
        if (!receiverInfo) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Receiver is no longer available.'
          }));
          return;
        }

        if (receiverInfo.peerId) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Receiver is currently in another session.'
          }));
          return;
        }

        // Initialize pairing process
        initiateHandshake(socketId, targetReceiverId);
        break;
      }

      case 'incoming-request-response': {
        // Receiver clicked Accept or Decline
        const { accept } = msg;
        console.log(`[Server] Receiver response to incoming request: ${accept ? 'ACCEPT' : 'DECLINE'}`);
        
        const senderId = clientInfo.peerId;
        const senderInfo = sockets.get(senderId);

        if (!accept) {
          if (senderInfo) {
            senderInfo.ws.send(JSON.stringify({
              type: 'connection-declined',
              message: 'The receiver declined the connection request.'
            }));
            senderInfo.peerId = null;
          }
          clientInfo.peerId = null;
          return;
        }

        // If accepted, wait for both to submit signatures in the 'auth-signature' step
        break;
      }

      case 'auth-signature': {
        const { signature } = msg;
        console.log(`[Server] Received cryptographic signature from ${clientInfo.role} (${socketId})`);
        
        clientInfo.challenges.signature = signature;

        const peerId = clientInfo.peerId;
        const peerInfo = sockets.get(peerId);

        if (!peerInfo) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Peer disconnected during authentication.'
          }));
          return;
        }

        // If both signatures are submitted, send them to the opposite sides for validation
        if (clientInfo.challenges.signature && peerInfo.challenges.signature) {
          // Send Sender signature to Receiver to verify
          peerInfo.ws.send(JSON.stringify({
            type: 'verify-peer-signature',
            signature: clientInfo.challenges.signature,
            challenge: clientInfo.challenges.sent,
            peerCert: clientInfo.cert
          }));

          // Send Receiver signature to Sender to verify
          clientInfo.ws.send(JSON.stringify({
            type: 'verify-peer-signature',
            signature: peerInfo.challenges.signature,
            challenge: peerInfo.challenges.sent,
            peerCert: peerInfo.cert
          }));

          console.log(`[Server] Cryptographic signatures exchanged for local verification.`);
        }
        break;
      }

      case 'verify-peer-result': {
        const { verified } = msg;
        console.log(`[Server] Peer ${socketId} reports verification status: ${verified}`);

        clientInfo.challenges.verified = verified;

        const peerId = clientInfo.peerId;
        const peerInfo = sockets.get(peerId);

        if (!verified) {
          ws.send(JSON.stringify({ type: 'error', message: 'Verification failed.' }));
          if (peerInfo) {
            peerInfo.ws.send(JSON.stringify({ type: 'error', message: 'Peer failed mutual authentication verification.' }));
            peerInfo.peerId = null;
          }
          clientInfo.peerId = null;
          return;
        }

        // Check if both sides have verified the mutual authentication signatures
        if (clientInfo.challenges.verified === true && peerInfo && peerInfo.challenges.verified === true) {
          console.log(`[Server] Mutual authentication succeeded between ${socketId} and ${peerId}. Session established.`);
          
          // Notify both that authentication succeeded and signaling can begin
          ws.send(JSON.stringify({ type: 'auth-success' }));
          peerInfo.ws.send(JSON.stringify({ type: 'auth-success' }));
        }
        break;
      }

      // Proxy WebRTC SDP offer, answer and ICE candidates
      case 'signal': {
        const peerId = clientInfo.peerId;
        const peerInfo = sockets.get(peerId);

        if (peerInfo) {
          peerInfo.ws.send(JSON.stringify({
            type: 'signal',
            signal: msg.signal
          }));
        } else {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Peer is offline.'
          }));
        }
        break;
      }

      case 'disconnect-peer': {
        const peerId = clientInfo.peerId;
        const peerInfo = sockets.get(peerId);

        if (peerInfo) {
          peerInfo.ws.send(JSON.stringify({
            type: 'peer-disconnected',
            message: 'Session closed by peer.'
          }));
          peerInfo.peerId = null;
          peerInfo.challenges = {};
        }

        clientInfo.peerId = null;
        clientInfo.challenges = {};
        
        ws.send(JSON.stringify({
          type: 'session-closed'
        }));
        break;
      }
    }
  });

  ws.on('close', () => {
    console.log(`[Server] Socket disconnected: ${socketId}`);
    const clientInfo = sockets.get(socketId);

    if (clientInfo) {
      // Clean up receiver entry
      if (clientInfo.code && receivers.get(clientInfo.code) === socketId) {
        receivers.delete(clientInfo.code);
      }

      // Clean up demo waitlists
      if (waitingDemoReceiverId === socketId) {
        waitingDemoReceiverId = null;
      }
      if (waitingDemoSenderId === socketId) {
        waitingDemoSenderId = null;
      }

      // Notify peer if in a session
      const peerId = clientInfo.peerId;
      const peerInfo = sockets.get(peerId);
      if (peerInfo) {
        peerInfo.ws.send(JSON.stringify({
          type: 'peer-disconnected',
          message: 'The connection was lost.'
        }));
        peerInfo.peerId = null;
        peerInfo.challenges = {};
      }

      sockets.delete(socketId);
    }
  });
});

const PORT = process.env.PORT || 9000;
server.listen(PORT, () => {
  console.log(`[Server] Signaling server listening on port ${PORT}`);
});
