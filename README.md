Good Bye Phishing Web
A simple Python-based tool designed to analyze potential phishing threats by examining HTML elements, domain information, and IP addresses of a given URL.

Features
HTML Analysis: Inspects for suspicious <form> tags, action attributes, and input field types that are common in phishing attempts.

Domain & IP Analysis: Retrieves WHOIS information (registration date, expiration, registrar) and the IP address of the domain. Includes enhanced WHOIS retry logic and domain age assessment.

Advanced Phishing Detection: The system no longer relies on a single keyword but analyzes combinations of phrases, context, and spelling patterns to identify potential phishing more accurately.

Redirect Detection: Basic static analysis for meta refresh and JavaScript redirects.

Latest Updates
The primary improvement in this version focuses on the risk detection system. The previously over-sensitive logic has been updated to be smarter and more contextual.

Updated Detection Logic: Instead of just flagging keywords like login or password as high-risk, the system now evaluates suspicious word combinations (e.g., verify account + immediately) within their context.

Typo-squatting Detection: Added the ability to detect intentionally misspelled words (typos) or similar characters (homoglyphs) used to impersonate trusted brands or services.

Reduced False Positives: By analyzing context, false positive warnings are expected to be significantly reduced, allowing users to focus more on genuine risks.

Installation
Follow the steps below to set up and run this tool in your local environment.

Prerequisites
Python 3.x installed on your system.

pip (Python package installer).

git (version control system) for cloning the repository.

Installation Steps (Linux/macOS)
Clone the repository:

git clone https://github.com/DieHukSho/GB-Phishing.git

Navigate to the project directory:

cd GB-Phishing

Create and activate a virtual environment (highly recommended):

python3 -m venv venv
source venv/bin/activate

Install the required dependencies:

pip install -r requirements.txt

Installation Steps (Windows - Command Prompt/PowerShell)
Clone the repository: Open Command Prompt (CMD) or PowerShell, then run:

git clone https://github.com/DieHukSho/GB-Phishing.git

Navigate to the project directory:

cd GB-Phishing

Create and activate a virtual environment (highly recommended):

For Command Prompt (CMD):

python -m venv venv
.\venv\Scripts\activate.bat

For PowerShell:

python -m venv venv
.\venv\Scripts\Activate.ps1

(You might need to allow script execution in PowerShell if it's blocked. Run Set-ExecutionPolicy RemoteSigned -Scope CurrentUser as administrator if you encounter issues.)

Install the required dependencies:

pip install -r requirements.txt

Example Output
  _______   ______     ______    _______     .______   ____    ____  _______                                       
 /  _____| /  __  \   /  __  \  |       \    |   _  \  \   \  /   / |   ____|                                      
|  |  __  |  |  |  | |  |  |  | |  .--.  |   |  |_)  |  \   \/   /  |  |__                                         
|  | |_ | |  |  |  | |  |  |  | |  |  |  |   |   _  <    \_    _/   |   __|                                        
|  |__| | |  `--'  | |  `--'  | |  '--'  |   |  |_)  |     |  |     |  |____                                       
 \______|  \______/   \______/  |_______/    |______/      |__|     |_______|                                      
                                                                                                                   
.______    __    __   __       _______. __    __   __  .__   __.   _______    ____    __    ____  _______ .______  
|   _  \  |  |  |  | |  |     /       ||  |  |  | |  | |  \ |  |  /  _____|   \   \  /  \  /   / |   ____||   _  \ 
|  |_)  | |  |__|  | |  |    |   (----`|  |__|  | |  | |   \|  | |  |  __      \   \/    \/   /  |  |__   |  |_)  |
|   ___/  |   __   | |  |     \   \    |   __   | |  | |  . `  | |  | |_ |      \            /   |   __|  |   _  < 
|  |      |  |  |  | |  | .----)   |   |  |  |  | |  | |  |\   | |  |__| |       \    /\    /    |  |____ |  |_)  |
| _|      |__|  |__| |__| |_______/    |__|  |__| |__| |__| \__|  \______|        \__/  \__/     |_______||______/ 
                                                                                                                                     
[+] Good Bye Phishing Web, Web Analyzer by DieHukShoo [+]                                                                                                                                                                           

Enter a Phishing URL to analyze (Example: https://malicious.com) or type 'exit' to quit: https://quexwakh.top/#/login
[+] Starting analysis for: https://quexwakh.top/#/login [+] Using a headless browser to clone: https://quexwakh.top/#/login [+] Waiting for login elements to appear... [!] Timeout: The website took too long to load. Falling back to the classic method. [!] Headless browser method failed. Attempting classic method. [+] Trying to clone with the classic method (without JavaScript): https://quexwakh.top/#/login
--- HTML Content & Phishing Element Analysis ---
url_analysis:{'URL': 'https://quexwakh.top/#/login'}
form_analysis:No tags were found.
script_analysis: No suspicious JavaScript functions found.
input_field_names_found: [] (Empty)
potential_data_targets: [] (Empty)
external_links: [] (Empty)
phishing_keywords_in_text: No common phishing keywords found. [*] Attempting WHOIS lookup for quexwakh.top (Attempt 1/3)...
--- Domain & IP Analysis ---
domain_name: quexwakh.top
creation_date: 2025-07-16 02:12:55
expiration_date: 2026-07-16 02:12:55
registrar: NameSilo, LLC
whois_server: whois.namesilo.com
name_servers: ['ns1.dnsowl.com', 'ns2.dnsowl.com', 'ns3.dnsowl.com']
domain_age_days: 19
domain_age_suspicion: Very New Domain (Less than 90 days) - HIGH PHISHING INDICATOR
registrar_privacy_service: No privacy/proxy service detected
ip_address: 38.60.198.81
GeoIP Information:
╒══════════════╤═════════════════════════════════╕
│ Field        │ Value                           │
╞══════════════╪═════════════════════════════════╡
│ Country      │ Singapore                       │
├──────────────┼─────────────────────────────────┤
│ Region       │ North West                      │
├──────────────┼─────────────────────────────────┤
│ City         │ Singapore                       │
├──────────────┼─────────────────────────────────┤
│ ISP          │ Kaopu Cloud HK Limited          │
├──────────────┼─────────────────────────────────┤
│ Organization │ Kaopu Cloud                     │
├──────────────┼─────────────────────────────────┤
│ ASN          │ AS138915 Kaopu Cloud HK Limited │
├──────────────┼─────────────────────────────────┤
│ Timezone     │ Asia/Singapore                  │
├──────────────┼─────────────────────────────────┤
│ Latitude     │ 1.35208                         │
├──────────────┼─────────────────────────────────┤
│ Longitude    │ 103.82                          │
╘══════════════╧═════════════════════════════════╛

[+] Core analysis complete.

--- Analysis Summary ---
Overall Phishing Risk Level: MEDIUM
Key Findings:
-   HIGH: The domain is very new (less than 90 days), a common phishing indicator.
-   MEDIUM: The domain uses a privacy protection service, which can be a red flag.

[!] Important Warning:
-   Always perform this analysis in a secure environment (VM/Sandbox), and consider using a VPN!
-   These results are initial findings; manual confirmation and further analysis are still required.

Press Enter to analyze another URL or type 'exit' to quit...

Usage
Once the installation is complete and your virtual environment is active, you can run the script using the following command:

python gb_phishing.py

Contributing
Contributions are welcome! If you find a bug or have a feature suggestion, please open an issue or submit a pull request.

License
This project is licensed under the MIT License. See the LICENSE file for more details.

Contact
For any questions, you can reach DieHukSho via GitHub.
