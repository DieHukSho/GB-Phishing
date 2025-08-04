# Good Bye Phishing Web

**Good Bye Phishing Web** is a simple Python-based tool designed to analyze potential phishing threats by examining HTML elements, domain information, and IP addresses of a given URL.

---

## 🔍 Features

- **HTML Analysis**  
  Inspects suspicious `<form>` tags, `action` attributes, and input field types commonly used in phishing attempts.

- **Domain & IP Analysis**  
  Retrieves WHOIS information (registration date, expiration, registrar), IP address, and assesses domain age and privacy services.

- **Advanced Phishing Detection**  
  Goes beyond single keywords to analyze phrase combinations, contextual patterns, and spelling anomalies for better accuracy.

- **Redirect Detection**  
  Includes basic static analysis for meta refresh tags and JavaScript-based redirects.

---

## ⚙️ Installation

### ✅ Requirements

- Python 3.x
- `pip` (Python package manager)
- `git` (to clone the repository)

---

### 🐧 Linux / macOS
```bash
git clone https://github.com/DieHukSho/GB-Phishing.git

cd GB-Phishing

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

###🪟 Windows (CMD or PowerShell)
powershell
git clone https://github.com/DieHukSho/GB-Phishing.git

cd GB-Phishing

# Command Prompt
python -m venv venv
.\venv\Scripts\activate.bat

# PowerShell
python -m venv venv

.\venv\Scripts\Activate.ps1

⚠️ If PowerShell blocks execution:
Run Set-ExecutionPolicy RemoteSigned -Scope CurrentUser as Administrator.
bash
pip install -r requirements.txt

##🚀 Usage
Once installed and your virtual environment is activated, run:
bash
python gb_phishing.py

##🙌 Contributing
Pull requests are welcome! If you find bugs or have feature suggestions, feel free to open an issue or submit a PR.

##📄 License
This project is licensed under the MIT License.
