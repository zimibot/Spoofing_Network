
# NetCut-like API
![Dashboard Screenshot](./screenshots/gambar.jpg)

NetCut-like API is a Python-based application built with Flask to manage ARP spoofing, network scanning, IP whitelisting, and more on a local network. This application allows you to perform network scans, start ARP spoofing attacks, manage whitelisted IPs, and provides a web-based dashboard for easy management.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [WinPcap Installation (For Windows)](#winpcap-installation-for-windows)
- [Usage](#usage)
  - [Running the Application](#running-the-application)
  - [Accessing the Dashboard](#accessing-the-dashboard)
  - [Running the `index.html` Locally](#running-the-index-html-locally)
  - [API Endpoints](#api-endpoints)
  - [Web Dashboard Functionality](#web-dashboard-functionality)
- [Running on Termux](#running-on-termux)
  - [Installation on Termux](#installation-on-termux)
  - [Running the API on Termux](#running-the-api-on-termux)
  - [Running `index.html` on Termux](#running-indexhtml-on-termux)
  - [Accessing the API on Termux](#accessing-the-api-on-termux)
- [Notes](#notes)
- [License](#license)

## Features

- **ARP Spoofing**: Start and stop ARP spoofing attacks on a specified network with the ability to customize the number of threads used.
- **Network Scanning**: Scan the local network to discover devices and their MAC addresses, with the option to load previously scanned devices from a JSON file.
- **IP Whitelisting**: Add and remove IPs from a whitelist to exclude them from ARP spoofing. The whitelist is stored in a JSON file for persistence.
- **Web-based Dashboard**: Manage all features from a simple web interface, including network scanning, ARP spoofing, and whitelist management.
- **Cross-Platform Support**: The application can run on both Windows (using WMI) and Linux/Android (using psutil) for network interface detection.
- **Periodic Network Scanning**: Automatically update the list of target IPs by periodically scanning the network.
- **Error Handling and Thread Management**: Forcefully stop ARP spoofing if any error occurs, ensuring safe thread management.
- **CORS Enabled**: Cross-Origin Resource Sharing is enabled for ease of use in diverse environments.

## Requirements

- Python 3.x
- Flask
- Flask-CORS
- Scapy
- WMI (for Windows)
- psutil (for Linux/Android)
- Netifaces
- Threading
- JSON

## WinPcap Installation (For Windows)

If you're running this application on Windows, you need **WinPcap** to allow Scapy to capture and inject packets. Here's how to install WinPcap:

1. **Download WinPcap**:
   - You can download WinPcap from the official website: [WinPcap Download](https://www.winpcap.org/install/default.htm).

2. **Install WinPcap**:
   - Run the installer and follow the on-screen instructions to complete the installation.

3. **Verify Installation**:
   - After installing WinPcap, verify that it is working by running the following command in a terminal:
     ```bash
     nping --version
     ```
   - If WinPcap is installed correctly, Scapy will be able to capture network packets.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/zimibot/Spoofing_Network.git
   cd netcut-like-api
   ```

2. **Install the Required Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install WMI on Windows** (if not installed):
   ```bash
   pip install WMI
   ```

4. **Run the Application**:
   ```bash
   python api.py
   ```

## Usage

### Running the Application
1. Start the Flask application by running `python api.py` in your terminal.
2. The API will be accessible on `http://localhost:5000`.
   - **Note**: Port `5000` is used exclusively for the API.

### Accessing the Dashboard
- The dashboard itself is not served by the Flask API. To access the dashboard, you need to open the `index.html` file separately.

### Running the `index.html` Locally

1. **Ensure the Flask API is Running**: Make sure the Flask API is running on your machine (`http://localhost:5000`).

2. **Open the `index.html` File Using Python**:
   - Navigate to the directory where `index.html` is located:
     ```bash
     cd /path/to/your/index.html
     ```
   - Start a simple HTTP server using Python:
     ```bash
     python -m http.server 8080
     ```
     This command will serve the files in the directory on port `8080`.

3. **Access the Dashboard**:
   - **From Your Computer**: Open a browser and go to `http://localhost:8080/index.html`.
   - **From Another Device**: Use the IP address of your machine (e.g., `http://<Your-IP>:8080/index.html`).

### API Endpoints
- **`GET /scan_interfaces`**: Scan available network interfaces and save them to JSON.
- **`GET /interface_data`**: Retrieve the list of network interfaces from the JSON file.
- **`GET /scan_network`**: Scan devices on the network, excluding whitelisted IPs.
  - Parameters: `interface` (Index of the network interface)
- **`GET /scan_network_data`**: Retrieve previously scanned network data from the JSON file.
- **`POST /start_netcut`**: Start ARP spoofing on specified IPs.
  - Parameters: `interface`, `target_ips`, `num_threads`
- **`POST /stop_netcut`**: Stop all running ARP spoofing attacks.
- **`POST /force_stop_netcut`**: Forcefully stop all running ARP spoofing attacks and clear the session.
- **`POST /whitelist`**: Add IPs to the whitelist.
  - Parameters: `ip` (The IP address(es) to be added)
- **`DELETE /whitelist`**: Remove IPs from the whitelist.
  - Parameters: `ip` (The IP address(es) to be removed)
- **`GET /whitelist`**: Get the list of whitelisted IPs.
- **`GET /help`**: Display API documentation and help information.

### Web Dashboard Functionality
- **Whitelist Management**: Add or remove IP addresses from the whitelist directly from the dashboard.
- **ARP Spoofing Management**: Start, stop, or force stop ARP spoofing attacks. Customize the target IPs and the number of threads used.
- **Network Scanning**: Perform network scans to discover devices. The scanned devices are displayed on the dashboard and can be used to select target IPs for ARP spoofing.
- **Multiple Target IP Selection**: Select multiple IP addresses from scanned devices to target with ARP spoofing, with an option to select "all" devices.
- **Error Notifications**: Receive real-time error notifications via pop-ups using SweetAlert2.

## Running on Termux

### Installation on Termux
> **Important**: Ensure that your device is rooted before proceeding. Root access is required to run ARP spoofing and network scanning on Android through Termux.

1. **Install Termux**: Download and install [Termux](https://termux.com/) from the Google Play Store or F-Droid.

2. **Update and Upgrade Termux Packages**:
   ```bash
   pkg update -y
   pkg upgrade -y
   ```

3. **Install Python and Pip**:
   ```bash
   pkg install python -y
   ```

4. **Install Required Python Packages**:
   ```bash
   pip install flask flask-cors scapy psutil netifaces
   ```

5. **Clone the Repository**:
   ```bash
   pkg install git -y
   git clone https://github.com/zimibot/Spoofing_Network.git
   cd Spoofing_Network
   ```

### Running the API on Termux
1. Start the Flask application in Termux:
   ```bash
   python api.py
   ```

### Running `index.html` on Termux

1. **Ensure the Flask API is Running**:
   - Ensure that your Flask API is running on `http://localhost:5000` by executing:
     ```bash
     python api.py
     ```

2. **Serve `index.html` Using Python**:
   - Install a Python HTTP server to serve the `index.html` file:
     ```bash
     cd /path/to/your/index.html
     python -m http.server 8080
     ```
   - This command will serve the files in the directory on port `8080`.

3. **Access the Dashboard**:
   - **From Your Android Device**: Open a web browser and navigate to `http://localhost:8080/index.html`.
   - **From Another Device**: Find the IP address of your Android device by running `ifconfig` in Termux. Access the dashboard using

 `http://<Your-IP>:8080/index.html`.

### Accessing the API on Termux
- **From Your Android Device**: Open a browser and go to `http://localhost:5000`.
- **From Another Device**: Find the IP address of your Android device by running `ifconfig` in Termux, then access the API using `http://<Your-IP>:5000`.

## Notes
- Ensure you have the proper permissions and legal rights to perform network scanning and ARP spoofing on the network you are testing.
- For Windows systems, ensure that the `wmi` module is installed and available.
- For Termux, make sure that the script correctly detects the environment and uses `psutil` for network interface detection.
- **Root access is required on Android** when using Termux to perform network scanning and ARP spoofing.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
