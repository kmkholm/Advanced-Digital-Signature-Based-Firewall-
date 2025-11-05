# Advanced Digital Signature Based Firewall 🛡️

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Cryptography](https://img.shields.io/badge/cryptography-RSA--2048-red.svg)]()

A sophisticated firewall application with GUI built using Python and tkinter, featuring digital signature authentication, packet filtering, and comprehensive rule management.

**Author:** Dr. Mohammed Tawfik  
**Contact:** kmkhol01@gmail.com  
**Version:** 1.0.0  
**Last Updated:** November 2024

---

## 📑 Table of Contents

- [Features](#-features)
- [Screenshots](#-screenshots)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Rule Examples](#rule-examples)
- [Architecture](#architecture)
- [Advanced Features](#advanced-features)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)
- [Support](#support)

---

## 📸 Screenshots

*See [GUI_VISUAL_GUIDE.md](GUI_VISUAL_GUIDE.md) for detailed ASCII mockups of all interface screens*

### Main Dashboard
```
┌─────────────────────────────────────────┐
│    Firewall Control Center              │
│  ┌────────────┐    ┌────────────┐      │
│  │   Start    │    │    Stop    │      │
│  └────────────┘    └────────────┘      │
│                                         │
│  Statistics:                            │
│  Total Packets: 1,234                   │
│  Allowed: 987 (Green)                   │
│  Blocked: 247 (Red)                     │
│  Active Rules: 13                       │
└─────────────────────────────────────────┘
```

---

## Features

### 🔒 Digital Signature Security
- **RSA Key Pair Generation**: Generate 2048-bit RSA key pairs for secure signing
- **Rule Signing**: Sign firewall rules with digital signatures to ensure integrity
- **Key Management**: Import/export public and private keys
- **Trusted Key Store**: Maintain a list of trusted public keys
- **Signature Verification**: Verify signatures on imported rules

### 🛡️ Firewall Capabilities
- **Packet Filtering**: Monitor and filter network traffic based on customizable rules
- **Protocol Support**: Support for TCP, UDP, ICMP, and ALL protocols
- **IP Address Filtering**: Support for specific IPs and CIDR notation (e.g., 192.168.1.0/24)
- **Port-based Filtering**: Filter traffic by source and destination ports
- **Action Control**: ALLOW or BLOCK traffic based on rules
- **Default Policy**: Configurable default action for unmatched traffic

### 📊 Monitoring & Statistics
- **Real-time Packet Monitor**: View incoming/outgoing packets in real-time
- **Traffic Statistics**: Track total, allowed, and blocked packets
- **Rule Hit Counters**: Monitor how many times each rule is triggered
- **Event Logging**: Comprehensive logging of all firewall events
- **Filtered View**: Filter packet display by ALLOWED/BLOCKED/ALL

### 🎛️ User Interface
- **Modern GUI**: Clean, intuitive interface using tkinter
- **Tabbed Interface**: Organized sections for Dashboard, Rules, Monitor, Signatures, and Logs
- **Interactive Dashboard**: Start/stop firewall with visual feedback
- **Rules Management**: Add, edit, delete, and organize firewall rules
- **Visual Indicators**: Color-coded allowed (green) and blocked (red) traffic

### 💾 Import/Export
- **Rule Export/Import**: Save and load firewall rules as JSON files
- **Key Export**: Export public and private keys in PEM format
- **Log Export**: Save event logs to text files
- **Rule Signatures**: Export signed rules with embedded signatures

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install cryptography
```

### Step 2: Run the Application
```bash
python advanced_firewall.py
```

Or make it executable (Linux/Mac):
```bash
chmod +x advanced_firewall.py
./advanced_firewall.py
```

## Usage Guide

### Starting the Firewall

1. **Launch the Application**: Run `python advanced_firewall.py`
2. **Dashboard**: You'll see the main dashboard with statistics
3. **Click "Start Firewall"**: This activates packet monitoring
4. **Monitor Traffic**: Switch to the "Packet Monitor" tab to see real-time traffic

### Managing Firewall Rules

#### Adding a Rule
1. Go to the "Firewall Rules" tab
2. Click "Add Rule"
3. Fill in the rule details:
   - **Action**: ALLOW or BLOCK
   - **Protocol**: ALL, TCP, UDP, or ICMP
   - **Source IP**: IP address or CIDR (e.g., 192.168.1.0/24) or "ANY"
   - **Source Port**: Port number or "ANY"
   - **Destination IP**: IP address or CIDR or "ANY"
   - **Destination Port**: Port number or "ANY"
   - **Description**: Brief description of the rule
4. Click "OK"

#### Editing a Rule
1. Select a rule from the list
2. Click "Edit Rule"
3. Modify the details
4. Click "OK"

#### Deleting a Rule
1. Select a rule from the list
2. Click "Delete Rule"
3. Confirm the deletion

#### Signing a Rule
1. Select a rule from the list
2. Click "Sign Rule"
3. The rule will be signed with your private key
4. A checkmark (✓) will appear in the "Signed" column

### Digital Signatures

#### Generating a New Key Pair
1. Go to the "Digital Signatures" tab
2. Click "Generate New Keypair"
3. Your new public key will be displayed
4. **Warning**: This replaces your existing keys

#### Exporting Keys
1. **Export Public Key**: Click "Export Public Key" and save the .pem file
2. **Export Private Key**: Click "Export Private Key" and save securely
   - ⚠️ **Warning**: Keep private keys secure! Never share them!

#### Importing Trusted Keys
1. Click "Import Trusted Key"
2. Select a .pem file containing a public key
3. The key will be added to your trusted keys list

### Packet Monitoring

1. Go to the "Packet Monitor" tab
2. Start the firewall from the Dashboard
3. Watch real-time traffic:
   - **Green text**: Allowed packets
   - **Red text**: Blocked packets
4. Use the filter dropdown to show only ALLOWED, BLOCKED, or ALL packets
5. Click "Clear" to clear the display

### Event Logs

1. Go to the "Event Logs" tab
2. View all firewall events with timestamps
3. Click "Export Logs" to save logs to a file
4. Click "Clear Logs" to clear the display

## Rule Examples

### Example 1: Block SSH from Internet
```
Action: BLOCK
Protocol: TCP
Source IP: ANY
Source Port: ANY
Destination IP: ANY
Destination Port: 22
Description: Block SSH from internet
```

### Example 2: Allow HTTPS from Local Network
```
Action: ALLOW
Protocol: TCP
Source IP: 192.168.1.0/24
Source Port: ANY
Destination IP: ANY
Destination Port: 443
Description: Allow HTTPS from local network
```

### Example 3: Block All Traffic from Specific IP
```
Action: BLOCK
Protocol: ALL
Source IP: 203.0.113.0
Source Port: ANY
Destination IP: ANY
Destination Port: ANY
Description: Block malicious IP
```

### Example 4: Allow DNS Queries
```
Action: ALLOW
Protocol: UDP
Source IP: 192.168.1.0/24
Source Port: ANY
Destination IP: ANY
Destination Port: 53
Description: Allow DNS queries
```

## Architecture

### Components

1. **DigitalSignatureManager**: Handles RSA key generation, signing, and verification
2. **FirewallRule**: Represents individual firewall rules with matching logic
3. **PacketMonitor**: Monitors network packets (simulated for demonstration)
4. **AdvancedFirewallGUI**: Main GUI application coordinating all components
5. **RuleDialog**: Dialog window for adding/editing rules

### Security Features

- **RSA-2048**: Uses 2048-bit RSA keys for strong security
- **SHA-256**: Uses SHA-256 hashing for signatures
- **PSS Padding**: Uses PSS (Probabilistic Signature Scheme) padding
- **Rule Integrity**: Signed rules cannot be modified without detection
- **Key Management**: Separate storage of public and private keys

## File Structure

```
advanced_firewall.py     # Main application
requirements.txt         # Python dependencies
README.md               # This file
```

## Advanced Features

### CIDR Notation Support
The firewall supports CIDR notation for IP ranges:
- `192.168.1.0/24` - Matches 192.168.1.1 to 192.168.1.254
- `10.0.0.0/8` - Matches 10.0.0.0 to 10.255.255.255

### Rule Priority
Rules are evaluated in order from top to bottom. The first matching rule determines the action.

### Signature Verification
When importing rules with signatures:
1. The signature is verified against trusted public keys
2. Invalid signatures are flagged
3. Unsigned rules are clearly marked

### Export/Import Workflow
1. **Export rules** with signatures from one system
2. **Transfer** the JSON file securely
3. **Import rules** on another system
4. **Verify** signatures using trusted public keys
5. **Deploy** verified rules

## Limitations & Notes

### Current Implementation Notes
- **Packet Monitor**: The current implementation simulates packet traffic for demonstration
- **Real Packet Capture**: For production use, integrate with libraries like:
  - `scapy` for packet capture
  - `pydivert` (Windows) for packet interception
  - `iptables` wrapper (Linux) for kernel-level filtering
- **Permissions**: Real packet capture may require administrator/root privileges

### Platform Considerations
- **Windows**: May need WinPcap or Npcap for real packet capture
- **Linux**: May need libpcap and root privileges
- **macOS**: May need libpcap and permissions adjustments

## Security Best Practices

1. **Protect Private Keys**: Never share or expose private keys
2. **Use Strong Passwords**: When exporting encrypted private keys
3. **Regular Backups**: Back up your rules and keys regularly
4. **Review Rules**: Periodically review and update firewall rules
5. **Monitor Logs**: Regularly check event logs for suspicious activity
6. **Test Rules**: Test new rules in a safe environment first
7. **Default Deny**: Use a default BLOCK rule at the end of your rule list

## Troubleshooting

### Application Won't Start
- Ensure Python 3.7+ is installed: `python --version`
- Check dependencies are installed: `pip list | grep cryptography`
- Try reinstalling: `pip install --force-reinstall cryptography`

### Can't Import Rules
- Verify the JSON file format is correct
- Check file permissions
- Ensure the file isn't corrupted

### Signature Verification Fails
- Ensure you have the correct public key imported
- Check that the rule hasn't been modified after signing
- Verify the key format is correct (PEM)

## Future Enhancements

Potential improvements for production use:
- Real packet capture using scapy or similar
- Integration with system firewall (iptables, Windows Firewall)
- Machine learning for anomaly detection
- Geo-IP filtering
- Rate limiting
- DPI (Deep Packet Inspection)
- VPN integration
- Cloud-based rule synchronization
- Mobile app for remote management

## Technical Details

### Cryptographic Standards
- **Algorithm**: RSA with 2048-bit keys
- **Padding**: PSS (Probabilistic Signature Scheme)
- **Hash**: SHA-256
- **Encoding**: PEM format for keys

### Network Support
- **IPv4**: Full support
- **IPv6**: Can be added by extending IP matching logic
- **Protocols**: TCP, UDP, ICMP, and custom protocols

## License

MIT License

Copyright (c) 2024 Dr. Mohammed Tawfik

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Author

**Dr. Mohammed Tawfik**  
📧 Email: kmkhol01@gmail.com  
🔬 Specialization: Network Security & Cryptography  

## Acknowledgments

This project demonstrates advanced concepts in:
- Network security and firewall implementation
- Digital signature authentication using RSA cryptography
- GUI development with Python tkinter
- Secure software architecture

## Citation

If you use this software in your research or project, please cite:

```
Dr. Mohammed Tawfik (2024). Advanced Digital Signature Based Firewall.
GitHub repository: [Your Repository URL]
```

## Disclaimer

This software is provided for educational and research purposes. While it implements
secure cryptographic practices, it should be thoroughly tested and audited before
any production deployment. The author is not responsible for any misuse or damage
caused by this software.

## Support

For questions, bug reports, or feature requests:
- 📧 Email: kmkhol01@gmail.com
- 🐛 Issues: Please open an issue on GitHub
- 💡 Contributions: Pull requests are welcome!

## Star History

If you find this project useful, please consider giving it a ⭐ on GitHub!

---

**Made with ❤️ by Dr. Mohammed Tawfik**  
*Advancing Network Security Through Innovation*
