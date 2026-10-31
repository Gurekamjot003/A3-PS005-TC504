# Autonomous BGP Update Anomaly Monitoring System (A3-PS005)

Hey there! 👋 Welcome to our project repository. This is our submission for the hackathon, where we built a high-performance, real-time BGP (Border Gateway Protocol) update anomaly monitoring system using Python and Radix Tree data structures.

If you want to see what this project is all about and how it performs in action, check out our videos below!

## 📺 Project Videos

| Resource | YouTube Link | Description |
| --- | --- | --- |
| **Introductory Video** | [Watch on YouTube](https://youtu.be/ddWUQlWI6V8) | A quick overview of our team, the problem statement, and our architectural approach. |
| **Live Working Demo** | [Watch on YouTube](https://youtu.be/rsqEHW8-8YM) | A walkthrough of the system running live, showing how it detects anomalies and handles MRT updates. |

---

## 🚀 What is This All About?

In the world of internet routing, BGP is the glue that holds the global routing table together. However, unexpected route leaks, prefix hijacks, and massive updates can destabilize networks.

Our system (**PS-005**) is designed to ingest BGP update streams (from raw MRT files), map prefixes efficiently using custom **Radix Tree data structures**, and monitor for anomalies in real-time. We wanted something lightweight, fast, and capable of processing large-scale routing data without choking up memory.

---

## 🛠️ Tech Stack & Architecture

* **Language:** Python 3.13
* **Core Data Structure:** Custom Radix Tree (for lightning-fast IP prefix lookups and route matching)
* **Data Sources:** MRT routing update dumps (e.g., `updates.20240627.1800.gz`)
* **Libraries:** Standard library + optimized parsing utilities for handling compressed BGP updates.

---

## 📁 Repository Structure

```text
.
├── README.md               # You are here!
├── requirements.txt        # Python dependencies
└── src/
    ├── README.md           # Detailed technical documentation for source files
    └── data/
        └── mrt/
            └── updates.20240627.1800.gz  # Sample MRT routing update dataset

```

---

## ⚙️ Quick Start & Installation

1. **Clone the repository:**
```bash
git clone https://github.com/gurekamjot003/a3-ps005-tc504.git
cd a3-ps005-tc504

```


2. **Install dependencies:**
```bash
pip install -r requirements.txt

```


3. **Run the monitoring engine:**
Head over to the `src/` directory and execute the main pipeline to process the sample MRT update dumps.

---

## 💡 How It Works (Briefly)

1. **Ingestion:** The system reads compressed MRT BGP update files line-by-line or record-by-record.
2. **Indexing:** Prefixes and their origin ASNs are indexed into our Radix Tree structure.
3. **Anomaly Detection:** As updates flow through, the engine checks route announcements against policy baselines and historical patterns to flag anomalous behavior instantly.

---

## 👥 Team & Acknowledgments

Built with ❤️ by our hackathon team **CICADA**. Feel free to drop us a note or check out the demo video for a deep dive into the code!
