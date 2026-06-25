# Basic Network Sniffer

A Python-based network packet sniffer built using the `scapy` library. This tool captures network traffic, extracts relevant information such as source/destination IP addresses, transport protocols (TCP/UDP/ICMP), and displays snippets of raw payload data. 

*Note: This project was developed as a learning exercise to understand network protocols and packet flows.*

## Prerequisites

Before running this tool, you must have the following installed:
1. **Python 3.x**
2. **Npcap (Windows Only):** Scapy requires the Npcap driver to capture network traffic on Windows. Download and install it from [npcap.com](https://npcap.com/). Linux and macOS users usually have `libpcap` installed by default or available via their package manager.

## Installation

1. Clone or download this repository.
2. Navigate to the folder in your terminal:
   ```bash
   cd BasicNetworkSniffer
   ```
3. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

**Important:** Packet sniffing requires low-level network access. You **must** run your terminal as an Administrator (Windows) or use `sudo` (Linux/macOS) to run this script.

1. Open your Command Prompt or Terminal as Administrator.
2. Run the script:
   ```bash
   python packet_sniffer.py
   ```
3. The tool will begin displaying captured packets in real-time.
4. Press `Ctrl + C` to stop the capture gracefully.

## Features
* Detects and parses IP layers.
* Identifies protocols: **TCP, UDP, and ICMP**.
* Extracts Source and Destination Port numbers.
* Attempts to decode and print the first 100 characters of a packet's Raw Payload safely.

## Ethical Disclaimer
This tool is intended for **educational purposes and network troubleshooting only**. Do not use this tool on any network where you do not have explicit permission to intercept traffic. Unauthorized packet sniffing is illegal and unethical.
