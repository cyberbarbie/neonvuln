# ⚡ NEONVULN — AI-Powered Vulnerability Scanner & LLM Automator  
A cyberpunk-themed AppSec tool that automates port scanning, exploit discovery, EPSS scoring, and AI-generated remediation guidance.

NeonVuln blends traditional security tooling with modern AI reasoning to create a lightweight but powerful workflow for authorized security assessments.

---

## ✨ Features

- 🔍 Runs **Nmap** service + port enumeration  
- 🧨 Uses **Searchsploit** to fingerprint known exploits  
- 📊 Pulls **EPSS (Exploit Prediction Scoring System)** data  
- 🧠 Leverages an **LLM** to generate:  
  - vulnerability summaries  
  - risk context  
  - actionable remediation steps  
  - verification steps  
  - references (NVD, advisories, etc.)
- 🌐 Clean, pastel-cyberpunk ASCII interface  
- 🔒 Built with safety rails for proper scope validation  

---

## 🛠️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/neonvuln.git
cd neonvuln

```
### 2. Create a Python virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```
Windows:
```powershell
venv\Scripts\activate
```
### 3. Install dependencies
```bash
pip install -r requirements.txt
```
### 4. Install required system tools
```bash
sudo apt install nmap exploitdb python3
```
### 5. Set your OpenAI API key
```bash
export OPENAI_API_KEY="your_key_here"
```
Windows:
```powershell
setx OPENAI_API_KEY "your_key_here"
```
## 🚀 Usage
Run the tool:
```bash
python appsec_agent.py
```
Enter your **authorized** target domain or IP when prompted:
```bash
example.com
```
NeonVuln will:

1. Normalize and validate the target

2. Run an Nmap service scan

3. Parse open ports

4. Run Searchsploit for each service

5. Extract CVEs

6. Query EPSS for likelihood scores

7. Send results to an LLM to generate a full remediation report

### 💜 Credits

Created with love by @cyberbarbie
Blending offensive recon + defensive remediation + AI reasoning into a single cyberpunk tool.