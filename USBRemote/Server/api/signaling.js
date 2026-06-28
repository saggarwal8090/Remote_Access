// USBRemote/Server/api/signaling.js
const { Pool } = require('pg');
const crypto = require('crypto');

// Initialize database connection pool
const connectionString = process.env.DATABASE_URL;
let pool = null;

if (connectionString) {
  pool = new Pool({
    connectionString,
    ssl: { rejectUnauthorized: false } // Required for Supabase / Neon
  });
}

// Helper to ensure database table is created
async function ensureTableExists() {
  if (!pool) return;
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS usb_remote_sessions (
        code VARCHAR(6) PRIMARY KEY,
        receiver_id VARCHAR(50) UNIQUE,
        receiver_cert JSONB,
        receiver_computer VARCHAR(100),
        sender_id VARCHAR(50) UNIQUE,
        sender_cert JSONB,
        sender_computer VARCHAR(100),
        challenge_sender VARCHAR(64),
        challenge_receiver VARCHAR(64),
        signature_sender TEXT,
        signature_receiver TEXT,
        verified_sender BOOLEAN DEFAULT FALSE,
        verified_receiver BOOLEAN DEFAULT FALSE,
        state VARCHAR(20) DEFAULT 'waiting', -- 'waiting', 'pairing', 'authenticating', 'success', 'declined'
        signals_to_sender JSONB DEFAULT '[]'::jsonb,
        signals_to_receiver JSONB DEFAULT '[]'::jsonb,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
  } catch (err) {
    console.error('Failed to verify table schema:', err);
  } finally {
    client.release();
  }
}

module.exports = async (req, res) => {
  // CORS Headers for API requests from Electron Client
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (!pool) {
    res.status(500).json({
      error: 'Database not configured. Please set the DATABASE_URL environment variable in Vercel.'
    });
    return;
  }

  // Ensure table exists on first execution
  await ensureTableExists();

  const urlPath = req.url.split('?')[0];

  try {
    switch (urlPath) {
      case '/api/register-receiver': {
        const { cert, computerName } = req.body;
        const receiverId = crypto.randomUUID();
        const code = Math.floor(100000 + Math.random() * 900000).toString();

        // Clear any old session with same code or receiver ID
        await pool.query('DELETE FROM usb_remote_sessions WHERE code = $1 OR receiver_id = $2', [code, receiverId]);

        await pool.query(
          `INSERT INTO usb_remote_sessions 
           (code, receiver_id, receiver_cert, receiver_computer, state, updated_at) 
           VALUES ($1, $2, $3, $4, 'waiting', CURRENT_TIMESTAMP)`,
          [code, receiverId, JSON.stringify(cert), computerName]
        );

        res.status(200).json({ success: true, code, receiverId });
        break;
      }

      case '/api/register-sender': {
        const senderId = crypto.randomUUID();
        res.status(200).json({ success: true, senderId });
        break;
      }

      case '/api/connect-request': {
        const { senderId, code, cert, computerName } = req.body;

        const sessionRes = await pool.query('SELECT * FROM usb_remote_sessions WHERE code = $1', [code]);
        if (sessionRes.rows.length === 0) {
          res.status(404).json({ error: 'Receiver code not found.' });
          return;
        }

        const session = sessionRes.rows[0];
        if (session.state !== 'waiting') {
          res.status(400).json({ error: 'Receiver is currently busy in another connection attempt.' });
          return;
        }

        // Generate challenges
        const challengeSender = crypto.randomBytes(32).toString('hex');
        const challengeReceiver = crypto.randomBytes(32).toString('hex');

        await pool.query(
          `UPDATE usb_remote_sessions SET
            sender_id = $1,
            sender_cert = $2,
            sender_computer = $3,
            challenge_sender = $4,
            challenge_receiver = $5,
            state = 'pairing',
            updated_at = CURRENT_TIMESTAMP
           WHERE code = $6`,
          [senderId, JSON.stringify(cert), computerName, challengeSender, challengeReceiver, code]
        );

        res.status(200).json({
          success: true,
          challenge: challengeSender,
          peerCert: session.receiver_cert,
          peerComputerName: session.receiver_computer
        });
        break;
      }

      case '/api/incoming-request-response': {
        const { receiverId, accept } = req.body;
        const state = accept ? 'authenticating' : 'declined';
        
        await pool.query(
          'UPDATE usb_remote_sessions SET state = $1, updated_at = CURRENT_TIMESTAMP WHERE receiver_id = $2',
          [state, receiverId]
        );
        res.status(200).json({ success: true });
        break;
      }

      case '/api/submit-signature': {
        const { id, role, signature } = req.body;
        
        if (role === 'sender') {
          await pool.query(
            'UPDATE usb_remote_sessions SET signature_sender = $1, updated_at = CURRENT_TIMESTAMP WHERE sender_id = $2',
            [signature, id]
          );
        } else {
          await pool.query(
            'UPDATE usb_remote_sessions SET signature_receiver = $1, updated_at = CURRENT_TIMESTAMP WHERE receiver_id = $2',
            [signature, id]
          );
        }
        res.status(200).json({ success: true });
        break;
      }

      case '/api/submit-verification': {
        const { id, role, verified } = req.body;

        if (!verified) {
          await pool.query('UPDATE usb_remote_sessions SET state = \'declined\' WHERE sender_id = $1 OR receiver_id = $1', [id]);
          res.status(200).json({ success: true, message: 'Verification failed reported.' });
          return;
        }

        if (role === 'sender') {
          await pool.query('UPDATE usb_remote_sessions SET verified_sender = TRUE WHERE sender_id = $1', [id]);
        } else {
          await pool.query('UPDATE usb_remote_sessions SET verified_receiver = TRUE WHERE receiver_id = $1', [id]);
        }

        // Check if both sides have verified
        const checkRes = await pool.query('SELECT * FROM usb_remote_sessions WHERE sender_id = $1 OR receiver_id = $1', [id]);
        if (checkRes.rows.length > 0) {
          const session = checkRes.rows[0];
          if (session.verified_sender && session.verified_receiver) {
            await pool.query('UPDATE usb_remote_sessions SET state = \'success\' WHERE code = $1', [session.code]);
          }
        }

        res.status(200).json({ success: true });
        break;
      }

      case '/api/poll': {
        const { id, role } = req.body;
        
        const sessionRes = await pool.query(
          'SELECT * FROM usb_remote_sessions WHERE sender_id = $1 OR receiver_id = $1',
          [id]
        );

        if (sessionRes.rows.length === 0) {
          res.status(200).json({ type: 'idle' });
          return;
        }

        const session = sessionRes.rows[0];

        // 1. Connection declined or peer disconnected
        if (session.state === 'declined') {
          await pool.query('DELETE FROM usb_remote_sessions WHERE code = $1', [session.code]);
          res.status(200).json({ type: 'declined', message: 'Connection declined or aborted by peer.' });
          return;
        }

        // 2. Incoming connection request for receiver
        if (role === 'receiver' && session.state === 'pairing') {
          res.status(200).json({
            type: 'incoming-request',
            challenge: session.challenge_receiver,
            peerCert: session.sender_cert,
            peerComputerName: session.sender_computer
          });
          return;
        }

        // 3. Challenge verification exchanges
        if (session.state === 'authenticating' || session.state === 'pairing') {
          if (role === 'sender' && session.signature_receiver && !session.verified_sender) {
            res.status(200).json({
              type: 'verify-peer-signature',
              signature: session.signature_receiver,
              challenge: session.challenge_sender,
              peerCert: session.receiver_cert
            });
            return;
          }
          if (role === 'receiver' && session.signature_sender && !session.verified_receiver) {
            res.status(200).json({
              type: 'verify-peer-signature',
              signature: session.signature_sender,
              challenge: session.challenge_receiver,
              peerCert: session.sender_cert
            });
            return;
          }
        }

        // 4. Verification success -> peer can signaling WebRTC
        if (session.state === 'success') {
          // Fetch signals and clear queue
          let signals = [];
          if (role === 'sender') {
            signals = session.signals_to_sender || [];
            if (signals.length > 0) {
              await pool.query('UPDATE usb_remote_sessions SET signals_to_sender = \'[]\'::jsonb WHERE sender_id = $1', [id]);
            }
          } else {
            signals = session.signals_to_receiver || [];
            if (signals.length > 0) {
              await pool.query('UPDATE usb_remote_sessions SET signals_to_receiver = \'[]\'::jsonb WHERE receiver_id = $1', [id]);
            }
          }

          res.status(200).json({
            type: 'active-session',
            signals: signals
          });
          return;
        }

        res.status(200).json({ type: session.state });
        break;
      }

      case '/api/send-signal': {
        const { id, role, signal } = req.body;

        const sessionRes = await pool.query(
          'SELECT * FROM usb_remote_sessions WHERE sender_id = $1 OR receiver_id = $1',
          [id]
        );

        if (sessionRes.rows.length === 0) {
          res.status(404).json({ error: 'Session not found.' });
          return;
        }

        const session = sessionRes.rows[0];

        if (role === 'sender') {
          // Send to receiver
          const currentQueue = session.signals_to_receiver || [];
          currentQueue.push(signal);
          await pool.query(
            'UPDATE usb_remote_sessions SET signals_to_receiver = $1 WHERE sender_id = $2',
            [JSON.stringify(currentQueue), id]
          );
        } else {
          // Send to sender
          const currentQueue = session.signals_to_sender || [];
          currentQueue.push(signal);
          await pool.query(
            'UPDATE usb_remote_sessions SET signals_to_sender = $1 WHERE receiver_id = $2',
            [JSON.stringify(currentQueue), id]
          );
        }

        res.status(200).json({ success: true });
        break;
      }

      case '/api/disconnect': {
        const { id } = req.body;
        await pool.query('DELETE FROM usb_remote_sessions WHERE sender_id = $1 OR receiver_id = $1', [id]);
        res.status(200).json({ success: true });
        break;
      }

      default:
        res.status(404).json({ error: 'Endpoint not found.' });
    }
  } catch (err) {
    console.error('API execution error:', err);
    res.status(500).json({ error: err.message });
  }
};
