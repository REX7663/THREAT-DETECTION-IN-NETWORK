<<<<<<< HEAD
# Threat-Detection-in-Network-Traffic
=======
# THREAT-DETECTION-IN-NETWORK-TRAFFIC
>>>>>>> 24ddb9a84ae074e7ba52425b5128f7dd42a56381
Real-Time Machine Learning Threat Detection System that analyzes network traffic to identify suspicious activities. It combines Nmap scanning, Wireshark packet analysis, and an Isolation Forest ML model to detect anomalies, assign risk severity levels, and display alerts through a Streamlit dashboard.

# Real-Time Machine Learning-Based Network Threat Detection System

## Overview

This project implements a **Real-Time Network Threat Detection System** using Machine Learning.  
It analyzes both **network exposure (Nmap scans)** and **network traffic behavior (Wireshark PCAP files)** to detect suspicious activity.

The system combines:

- Network scanning analysis
- Traffic flow analysis
- Machine learning anomaly detection
- Real-time packet monitoring
- Unified threat scoring
- Interactive security dashboard

The goal is to provide an **intelligent, automated threat detection tool** capable of identifying abnormal network behavior without relying on predefined attack signatures.

---

# Project Objectives

The system was developed to achieve the following objectives:

1. Extract and analyze open ports from **Nmap XML scan results**
2. Capture and analyze network traffic from **Wireshark PCAP/PCAPNG files**
3. Implement **real-time packet sniffing** for live monitoring
4. Convert packet data into **flow-level network features**
5. Engineer features for anomaly detection
6. Apply **Isolation Forest machine learning algorithm** to detect anomalies
7. Combine scanning and traffic data into a **unified threat model**
8. Compute **combined risk scores**
9. Classify threats into **LOW, MEDIUM, and HIGH severity**
10. Provide a **visual dashboard for monitoring and exporting results**

---

# System Architecture

The system integrates multiple modules:
Nmap Scan Module
↓
Exposure Feature Extraction
↓
Wireshark Traffic Module
↓
Flow Feature Extraction
↓
Unified Feature Dataset
↓
Isolation Forest Model
↓
Threat Scoring
↓
Severity Classification
↓
Streamlit Dashboard


The system therefore analyzes both **static network exposure** and **dynamic network traffic behavior**.

---

# Technologies Used

| Technology | Purpose |
|--------|--------|
| Python | Main programming language |
| Streamlit | Web dashboard interface |
| Scapy | Packet capture and PCAP analysis |
| Nmap | Network scanning |
| Wireshark | Traffic capture |
| Pandas | Data manipulation |
| Scikit-learn | Machine learning algorithms |
| Isolation Forest | Anomaly detection model |

---

# Project Folder Structure


ThreatDetectionProject/
│
├── data/
│ ├── nmap_scan.xml
│ └── traffic.pcapng
│
├── output/
│ ├── flows_with_anomalies.csv
│ ├── unified_results.csv
│ └── alerts_log.txt
│
├── src/
│ │
│ ├── app.py
│ │
│ ├── core/
│ │ ├── nmap.py
│ │ ├── pcap.py
│ │ ├── models.py
│ │ ├── unified.py
│ │ └── explain.py
│ │
│ ├── scripts/
│ │ ├── nmap/
│ │ └── pcap/
│ │
│ └── live/
│ └── live monitoring scripts
│
└── README.md


---

# Installation Guide

## 1 Install Python

Ensure Python **3.10 or later** is installed.

Check installation:


python --version


---

## 2 Install Required Libraries

Install dependencies:


pip install streamlit scapy pandas scikit-learn matplotlib


---

## 3 Install Nmap

Download and install from:

https://nmap.org/download.html

Verify installation:


nmap --version


---

# Running the System

Navigate to the project source directory:


cd ThreatDetectionProject/src


Launch the dashboard:


streamlit run app.py


The dashboard will open automatically in your browser:


http://localhost:8501


---

# Dashboard Features

The system interface contains **three main tabs**.

### Tab 1 — Nmap XML Scanner

Upload Nmap scan results to analyze exposed services.

Features:

- Port extraction
- Exposure feature analysis
- CSV export

---

### Tab 2 — Wireshark Traffic Analysis

Upload PCAP or PCAPNG traffic capture files.

Features:

- Packet processing
- Flow aggregation
- Anomaly detection
- Severity classification
- Alert explanations
- CSV export

---

### Tab 3 — Unified Risk Score

Combines exposure data and traffic behavior.

Features:

- Combined anomaly scoring
- Threat prioritization
- Unified dataset export

---

# Machine Learning Model

The system uses the **Isolation Forest algorithm**.

Isolation Forest works by:

1. Randomly partitioning data
2. Isolating rare observations
3. Assigning anomaly scores

Advantages:

- No labeled data required
- Effective for network anomaly detection
- Works with high dimensional data

---

# Threat Severity Classification

Threats are categorized based on anomaly score:

| Score Range | Severity |
|--------|--------|
| ≤ -0.20 | HIGH |
| -0.20 to -0.05 | MEDIUM |
| > -0.05 | LOW |

This helps administrators prioritize security alerts.

---

# Example Output

Example anomaly detection output:

| IP | Port | Service | Score | Severity |
|----|----|----|----|----|
| 10.0.0.254 | 8291 | unknown | -0.24 | HIGH |
| 10.0.0.254 | 2000 | cisco-sccp | -0.08 | MEDIUM |
| 10.0.0.254 | 443 | https | 0.05 | LOW |

---

# Testing the System

To demonstrate the system functionality:

1. Upload **Nmap XML scan results**
2. Upload **Wireshark traffic capture**
3. Run anomaly detection
4. Export CSV reports
5. Observe generated alerts

Testing results confirm the system successfully identifies abnormal network activity.

---

# Limitations

Current system limitations include:

- No deep packet payload inspection
- No automated firewall blocking
- Single-machine deployment
- Limited training dataset

---

# Future Improvements

Possible future enhancements include:

- Deep learning models for intrusion detection
- Automated response mechanisms
- Integration with SIEM platforms
- Distributed network sensors
- Cloud-based monitoring architecture

---

# Author

Student Name: *SONGMENE REX FRANCK*
Program: Higher National Diploma (HND) in Software Engineering  
Institution: Kelden Bilingual Higher Institute of Professional Studies  
Academic Year: 2025–2026

---

# License

This project was developed for academic purposes as part of a Higher National Diploma research project.
