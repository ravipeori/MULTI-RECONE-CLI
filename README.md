# 🔎 Multi-Recon CLI Tool

A high-level **offensive security & reconnaissance CLI tool** for Unix/Linux users.  
Built with Python, this tool combines **subdomain discovery, port scanning, WHOIS lookups, directory brute-forcing, banner grabbing, and more** into a single interface.

---

## ✨ Features
- Subdomain Enumeration (from wordlists + DNS resolution)
- Port Scanning (common + custom ranges)
- WHOIS Lookup
- Reverse DNS Lookup
- Directory Bruteforce (using wordlists)
- Banner Grabbing
- IP & Domain Info Fetcher
- Auto-Save Results (`txt` & `json`)
- Modular CLI Menu (easy to extend)

---

## ⚡ Installation

```bash
# Clone the repo
git clone https://github.com/your-username/multi-recon-cli.git
cd multi-recon-cli

# Install dependencies
pip install -r requirements.txt

🚀 Usage
# Run the tool
python3 tool.py


Example:

python3 tool.py -d example.com -s all

📂 Project Structure
multi-recon-cli/
│── tool.py                # Main CLI script
│── requirements.txt       # Dependencies
│── README.md              # Documentation
│── LICENSE                # Open-source license
│── .gitignore             # Ignore cache/logs
│── wordlists/             # Wordlists
│    ├── subdomains.txt
│    └── dirs.txt

📝 Example Run
[SERVER] Starting Recon on: example.com

[1] Subdomains Found:
    - www.example.com
    - mail.example.com
    - blog.example.com

[2] Open Ports:
    - 80 (HTTP)
    - 443 (HTTPS)

[3] Directory Bruteforce Results:
    - /admin
    - /uploads
    - /login

🛠 Requirements

Python 3.8+

requests

dnspython

python-whois

📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

⚠️ Disclaimer

This tool is for educational & security research purposes only.
Do not use it against systems you don’t own or don’t have permission to test.
