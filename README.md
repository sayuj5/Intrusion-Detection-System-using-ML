# 🛡️ NetSentinel: Cybernetic Intrusion Detection System (IDS)

An advanced Machine Learning-driven Network Defense Engine, featuring a real-time predictive backend and a high-performance, responsive Next.js frontend dashboard. 

## 🌐 Complete System Architecture

NetSentinel leverages a fast Python-based backend that actively sniffs packets and utilizes an ML model to detect anomalies. The events are streamed instantly to a visually striking, glassmorphic Next.js Dashboard.

### Backend (Python)
- `app.py`: The Main Server relaying real-time stats and events over Socket.IO.
- `prediction_api.py`: The ML Inference Engine processing packet data.
- `realtime_sniffer.py`: The core packet capturing service utilizing Scapy for active listening on Windows/Linux environments.

### Frontend (Next.js)
- A modern `Next.js 14` + `Tailwind CSS v4` dashboard.
- Uses `socket.io-client` for persistent real-time streaming.
- Fully responsive styling containing advanced glassmorphism and animated components to track detected attacks instantaneously.

## 🚀 Environment Setup

### 1. The Machine Learning Engine & Backend
First, ensure your Python environment is set up. From the root directory:
```bash
pip install -r requirements.txt
```

Launch the detection APIs across three terminals to bring the backend online:
```bash
python app.py
python prediction_api.py
python realtime_sniffer.py
```

### 2. The Next.js Interface
Switch to the built-in React UI dashboard folder and run the developer server.
```bash
cd frontend
npm install
npm run dev
```

Navigate to `http://localhost:3000` to review real-time security events!

## 🔐 Licensing
This software encompasses the MIT License terms. See `LICENSE.md` for copyright terms.
