# Advanced DoS Attack Detector and Network Analyzer

## Overview

This project provides a robust and advanced tool for detecting various types of Denial-of-Service (DoS) attacks and analyzing network traffic. The tool is capable of detecting attacks such as Deauthentication, Disassociation, SYN flood, UDP flood, ICMP flood, and FIN-ACK flood attacks.

## Features

- **Protocol Coverage**: Detects a variety of DoS attack types, including Deauthentication, Disassociation, SYN flood, UDP flood, ICMP flood, and FIN-ACK flood attacks.
- **Argument Parsing**: Uses `argparse` to handle command-line arguments for network interface, threshold, time window, and output file.
- **Logging**: Enhanced logging mechanism for better tracking of events and potential attacks. Logs can be written to a specified output file.
- **Multi-threading**: Utilizes threading to handle packet analysis and logging concurrently, improving performance and responsiveness.
- **Packet Count Thresholds**: Allows setting thresholds for different types of packets within a configurable time window, improving detection accuracy.
- **Cleanup Mechanism**: Implements periodic cleanup of packet count data to manage memory usage and maintain performance.

## Installation

### Prerequisites

- Python 3.x
- Scapy

You can install Scapy using pip:

```bash
pip install scapy
```

## Cloning the Repository
```bash
git clone https://github.com/Mostafa-Samy-97/dosdetector.git
cd dosdetector
```


Usage
## Running the Network Analyzer
```bash
python dosdetector.py -i <interface> -t <threshold> -w <time window> -o <output file>
```
-i, --interface: Network interface to monitor (required).
-t, --threshold: Packet count threshold for DoS detection (default: 100).
-w, --window: Time window for packet count (in seconds, default: 60).
-o, --output: Output file to save attack logs (optional).


Example Usage
```bash
python dosdetector.py -i wlan0 -t 100 -w 60 -o attacks.log
```


## Running Tests
### The project includes a comprehensive set of unit tests to ensure the functionality of the NetworkAnalyzer.

To run the tests, use the following command:
```bash
python -m unittest test_dos_detector.py
```

## License
This project is licensed under the MIT License. See the LICENSE.txt file for details.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request or open an issue.


