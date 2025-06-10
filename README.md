NetSentinel: A Machine Learning-Based Intrusion Detection System
A vigilant and adaptive shield for network defense, powered by real-time machine learning.

Table of Contents

1. About the Project
2. Features
3. Technologies Used
4. Dataset Used
5. Machine Learning Model
6. System Architecture
7. Installation & Setup
8. Usage
   8.1 Running the Application
   8.2 Dashboard Interaction
   8.3 Manual Intrusion Detection
   8.4 Packet Testing (Live Traffic)
9. Project Team
10. Future Scope
11. License
12. References


1 About the Project
NetSentinel stands as a cutting-edge Machine Learning-Based Intrusion Detection System (IDS) meticulously engineered to safeguard modern networks against evolving cyber threats. This sophisticated platform seamlessly integrates a high-performance scapy-driven real-time packet sniffer with a dynamic Flask web application, powered by a finely-tuned Random Forest model. This model is comprehensively trained on the NSL-KDD dataset, a widely recognized benchmark for IDS evaluation containing diverse network connection records labeled as normal or various attack types, enabling intelligent anomaly detection.

Beyond conventional monitoring, NetSentinel actively analyzes live network traffic, leveraging its advanced machine learning capabilities to swiftly discern between benign and malicious activities. It proactively identifies diverse attack vectors, from subtle anomalies to overt brute-force attempts like SSH attacks, presenting critical insights through an intuitive, real-time dashboard. Furthermore, the system rigorously logs every session, generating comprehensive historical reports vital for forensic analysis and robust security posture enhancement. NetSentinel redefines network defense by providing unparalleled visibility, automated threat intelligence, and a vigilant, adaptive shield against the digital landscape's persistent challenges.

2 Features

2.1 Real-time Packet Sniffing: Captures live network traffic for continuous monitoring.

2.2 Machine Learning-Based Detection: Utilizes a Random Forest classifier to detect anomalies and potential intrusions.

2.3 Rule-Based Attack Identification: Identifies specific attack types (e.g., SSH attempts) using predefined rules.

2.4 Interactive Web Dashboard: Provides a user-friendly interface for visualizing real-time network statistics, intrusion alerts, and attack distributions.

2.5 Live Event Logging: Displays a chronological log of all detected intrusion events.

2.6 Historical Reporting: Generates and stores detailed reports for each sniffing session, enabling retrospective analysis.

2.7 Manual Detection Panel: Allows users to input network features manually to test the ML model's prediction capabilities on demand.

3 Technologies Used
3.1 Backend & ML:

3.1.1 Python (3.8+)
3.1.2 Flask (Web Framework)
3.1.3 Flask-SocketIO (Real-time communication)
3.1.4 scikit-learn (Machine Learning)
3.1.5 Pandas & NumPy (Data Handling)
3.1.6 Scapy (Packet Sniffing)
3.1.7 Requests (HTTP communication)
3.1.8 Joblib (Model Serialization)

3.2 Frontend:
3.2.1 HTML, CSS (Tailwind CSS, if used, otherwise standard CSS)
3.2.2 JavaScript
3.2.3 Chart.js (Interactive Charts)
3.2.4 Leaflet.js (Geographical Maps - Note: GeoIP lookup functionality might be removed for simplicity in some versions.)

3.3 Utilities:
3.3.1 UUID (Session IDs)
3.3.2 datetime (Timestamping)
3.3.3 threading (Concurrency for sniffer)
3.3.4 Npcap (Windows packet capture driver)

3.4 Data Storage:
JSON (reports.json for session history)

4 Dataset Used
The core machine learning model within NetSentinel is comprehensively trained on the NSL-KDD dataset.

Characteristics: NSL-KDD is a widely recognized benchmark dataset for Intrusion Detection Systems (IDS) evaluation. It is a refined version of the KDD Cup '99 dataset, addressing its limitations such as redundant records and disproportionate class distribution. It contains diverse network connection records, each meticulously labeled as either 'normal' traffic or various 'attack' types (e.g., Denial of Service - DoS, Probe, User-to-Root - U2R, Remote-to-Local - R2L). This rich dataset enables the Random Forest model to learn intricate patterns associated with network intrusions effectively.

5 Machine Learning Model
The heart of NetSentinel's detection capability is the Random Forest Classifier:

5.1 Ensemble Learning: This algorithm builds a multitude of individual decision trees during training. Each tree is trained on a random subset of the data and features.

5.2 Robust Classification: For incoming network traffic, each tree makes its own prediction. The final classification (e.g., 'Normal Traffic' or 'Attack Detected!') is determined by a majority vote among all the trees.

5.3 Key Advantages: Random Forests are highly accurate, robust to overfitting, can handle high-dimensional data, and are effective with imbalanced datasets (crucial for IDS where attacks are rare) when configured with class_weight='balanced'.

6 System Architecture
NetSentinel operates through an integrated workflow:

6.1 Offline Training: The Random Forest model is trained using the NSL-KDD dataset. The trained model and preprocessing artifacts (scaler, encoders) are saved.

6.2 Live Capture: realtime_sniffer.py continuously captures raw packets from the network interface.

6.3 Data Forwarding: Parsed packet data, along with basic rule-based attack indicators, is sent via HTTP POST requests to the Flask app.py server.

6.4 Real-time Analysis: app.py loads the pre-trained ML model, processes incoming packets, classifies them (Normal/Attack), and aggregates real-time statistics.

6.5 Dynamic Dashboard: Using WebSockets (Flask-SocketIO), app.py pushes live updates to the index.html web dashboard, providing instant visualizations.

6.6 Historical Reporting: Upon session termination, app.py compiles and saves a detailed report (including raw packets and alerts) to reports.json.

7 Installation & Setup
Follow these steps to get NetSentinel up and running on your local machine:

7.1 Clone the Repository:
git clone https://github.com/your-username/NetSentinel-IDS.git
cd NetSentinel-IDS

7.2 Install Npcap (Windows Only):
If you are on Windows, download and install the latest Npcap from https://nmap.org/npcap/.
Crucial Step: During installation, select the option "Install Npcap in WinPcap API-compatible Mode". This is essential for Scapy to function correctly.

7.3 Create and Activate a Python Virtual Environment (Highly Recommended):
python -m venv venv
# On Windows:
.\venv\Scripts\activate

7.4 Install Python Dependencies:

7.4.1 Ensure your virtual environment is active.

7.4.2 Install the required libraries using the requirements.txt file (which you should create based on the "Technologies Used" section above):
pip install -r requirements.txt

7.5 Verify Installations (Optional):
pip freeze

8 Usage
8.1 Running the Application

8.1.1 Train the Machine Learning Model:

8.1.2 Open your terminal/command prompt and navigate to the project's root directory.

8.1.3 Run the model training script. This will download the NSL-KDD dataset and save the trained model artifacts.
python model.py

8.2 Start the Flask Web Server:
In the same terminal (or a new one, ensuring the virtual environment is active), run the Flask application:
python app.py
The server will typically start on http://127.0.0.1:5000/.

8.3 Start the Real-time Packet Sniffer:

8.3.1 Open another separate terminal/command prompt.

8.3.2 Activate the virtual environment.

8.3.3 Run the sniffing script:

python realtime_sniffer.py

8.3.4 The sniffer will automatically attempt to detect and sniff on an available network interface. Press Ctrl+C in this terminal to stop the sniffer and finalize the session report.

8.4 Dashboard Interaction

8.4.1 Open your web browser and navigate to http://127.0.0.1:5000/.

8.4.2 Dashboard Tab: View real-time statistics, intrusion rates, attack type distributions, and top attacker IPs.

8.4.3 Events Tab: See a live stream of detected intrusion events with details.

8.4.4 Live Traffic Tab: Observe raw network packets being captured in real-time.

8.4.5 Reports Tab: Browse and view detailed summaries and full packet logs from past sniffing sessions.

8.4.6 Manual Test Tab: Experiment with direct model predictions (see "Manual Intrusion Detection" below).

8.5 Manual Intrusion Detection
The "Manual Test" tab allows you to feed specific network feature values into the ML model to see its prediction.
8.5.1 Go to the "Manual Test" tab in the dashboard.

8.5.2 Input values for the 19 network traffic features (e.g., duration, protocol_type, service, flag, src_bytes, dst_bytes, count, serror_rate, etc.).

8.5.3 Click the "Predict" button.

8.5.4 Observe the model's prediction ("Normal Traffic" or "Attack Detected!") and the prediction probability pie chart.

8.6 Packet Testing (Live Traffic)
To simulate and test real-time detection:
8.6.1 Ensure both app.py and realtime_sniffer.py are running.

8.6.2 Use external tools (e.g., Nmap for port scans, Hydra for SSH brute-force) from another machine (e.g., a Kali Linux VM on the same network) to generate malicious traffic targeting the NetSentinel host.

8.6.3 Observe alerts and statistics updating in real-time on your dashboard.

9 Project Team

Sayuj Sur: Head & Machine Learning Specialist

Mabud Munshi: Backend Developer

Md. Mehetab Baidya: Frontend Developer / UI/UX & Performer

Ujjwal Kumar Mishra: Documentation & Reporting

10 Future Scope

Advanced Threat Intelligence: Integration with external threat feeds and dynamic blacklist/whitelist features.

Deep Learning Models: Exploration of more complex neural network architectures for enhanced detection capabilities.

Automated Response: Implementation of active response mechanisms (e.g., blocking IPs, isolating hosts).

Scalability & Deployment: Transition to robust database solutions (e.g., MongoDB, PostgreSQL) and containerization with Docker.

User Management: Secure user authentication and role-based access control.

Enhanced UI/UX: Further dashboard refinements, custom alert thresholds, and advanced filtering.

Protocol-Aware Analysis: Deeper analysis of application-layer protocols for nuanced threat detection.

11 License

This project is licensed under the MIT License(LICENSE.md) - see the LICENSE.md file for details.
