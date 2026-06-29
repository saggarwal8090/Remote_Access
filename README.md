# 🛡️ USB Remote Connect

A secure, zero-click remote desktop screen sharing application. It uses **mutual cryptographic RSA signature checks** on removable USB keys to authenticate clients, separating connections into isolated workspaces to support multiple simultaneous users.

---

## 🚀 Key Features

* **Mutual USB Authentication**: Authentication relies on RSA-2048 keys stored on actual physical USB drives. No passwords or databases are used.
* **Workspace Isolation Rooms**: Group clients into custom workspaces to prevent Senders from pairing with arbitrary receivers in a multi-user environment.
* **Explicit Sender Whitelisting**: Receivers explicitly specify the name of the Sender they wish to allow, preventing unauthorized connections.
* **Hands-Free Auto-Login**: The app automatically detects key insertions, reads certificates, and initiates connections in the background.
* **Programmatic Screen Capturing**: Native integration with Electron's OS window selectors allows receivers to stream their screens automatically without browser-chooser popups.
* **Secure Web Console**: A client version accessible directly in browsers using the native **Web Crypto API** for zero-install endpoints.

---

## 📦 System Architecture

```
USBRemote/
├── Client/                  # Desktop Electron Client
│   ├── src/                 # React UI Dashboard
│   ├── main.js              # Electron Main Process (USBWatcher & Capture APIs)
│   └── preload.js           # Bridge API
├── Server/                  # WebSocket Signaling Server
│   ├── server.js            # Node.js Signaling Broker
│   └── public/              # Static Web Console Assets
```

---

## 🛠️ Installation & Setup

### Prerequisites
* **Node.js** (v18 or higher)
* **npm** (v9 or higher)

### 1. Initial Setup
Clone the repository and install all dependencies:
```bash
# In the workspace root directory
npm run install-all
```

### 2. Launching Services Locally
```bash
# Start signaling server & client app concurrently
npm start
```
* The local signaling server will listen on port `9000`.
* The Electron desktop application will boot automatically.

---

## 🔑 How to Setup a USB Security Key

1. Connect a physical USB pendrive to your computer.
2. In the sidebar of the desktop app, you should see the drive letter appear under **USB Security Keys**.
3. Select the drive letter, enter an alias label (e.g. `Office Key`), and click **Format & Sign**.
4. The system will write the private key (`key.pem`) and certificate identity (`certificate.json`) inside a hidden `.usbremote/` directory on your USB drive.

---

## 🖥️ Step-by-Step Connection Guide

To establish a secure screen sharing link between two computers:

### Step 1: Set Workspace Room (On Both PCs)
1. Open the application.
2. You will be greeted by the **Secure Session Workspace** setup page.
3. Enter a common workspace name (e.g. `engineering-team`) and click **Enter Session Workspace**. Both users **must enter the exact same name** to connect.

### Step 2: Insert USB Key
* Plug your registered USB Security Key into the USB port. The app will automatically read the certificate, show your key details in the sidebar, and start a 5-second auto-launch countdown.

### Step 3: Choose Roles & Connect
* **Receiver (User sharing their screen)**:
  1. Click **Receiver** (or wait for the countdown).
  2. You will be prompted to authorize a Sender. Type the **Computer Name** or **Certificate Label** of the Sender you want to allow (e.g., `Rajnish-Laptop`) and click **Start Standby**.
  3. The Receiver will register on the Render server under your workspace name and await connection.
* **Sender (User controlling/viewing screen)**:
  1. Click **Sender** (or wait for countdown).
  2. The Sender registers on the signaling server under the same workspace name.
  3. The server checks the room. If it finds the Receiver whitelisting the Sender's name, it **automatically pairs them**.
  4. Challenge-response checks execute instantly, signatures verify, and the Receiver begins capturing the screen in the background. The Sender's viewport will load the live stream immediately!

---

## 🌐 Web Console (Zero-Install Browser Access)

For users who want to connect without installing the desktop app, they can access the Web Console directly:

1. Open your live link: **[https://remote-access-7j7a.onrender.com/](https://remote-access-7j7a.onrender.com/)**
2. Enter your workspace room name.
3. **If you don't have key files**: Type a label in the helper box at the bottom and click **Generate Keypair** to download them. Save them to your USB drive.
4. **Login**: Drag and drop your `certificate.json` and `key.pem` files into the designated drop zones, then click **Unlock Web Console**.
5. Select **Sender** or **Receiver** (Receiver types the allowed Sender name).
6. Pair and share your screen using direct browser WebRTC.

---

## 🛡️ Security Audit Logs
Every cryptographic signature check, registration, WebSocket exchange, and connection event is written locally in the application under the **Security Audit Log** tab. Use this to verify that only whitelisted, mutually verified certificates are accessing your workspace.
