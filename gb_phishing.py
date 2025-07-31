import requests
from bs4 import BeautifulSoup
import whois
import socket
from urllib.parse import urlparse, urljoin
import re
from datetime import datetime, timedelta # For domain age calculation
import time # For retry mechanism

# --- CORE FUNCTIONS ---
def get_html_content(url):
    """
    Retrieves HTML content from a given URL using basic requests (no JavaScript rendering).
    Handles common request errors.
    """
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True, verify=True)
        response.raise_for_status() # Raises HTTPError for 4xx/5xx status codes
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"[-] Error retrieving web content from {url}: {e}")
        return None
    
def analyze_html_clues(html_content, phishing_url):
    clues = {}
    # --- Form Analysis (More Sharpened) ---
    # Menambahkan analisis URL sebagai petunjuk
    clues['url_analysis'] = [{'URL Analysis': phishing_url}]

    # Analisis Form
    if "<form" not in html_content:
        clues['form_analysis'] = [{'Form Analysis': "No <form> tags found."}]
    else:
        clues['form_analysis'] = [{'Form Analysis': "Form tag detected, possibly collecting credentials."}]

    # Analisis Script mencurigakan
    if "eval(" in html_content or "escape(" in html_content:
        clues['script_analysis'] = [{'Script Analysis': "Suspicious JavaScript functions found (e.g., eval, escape)."}]

    return clues

    # --- Form Analysis ---
    form_details = []
    forms = soup.find_all('form')
    if forms:
        for i, form in enumerate(forms):
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET').upper() # Default to GET if not specified

            full_action_url = urljoin(base_url, form_action)

            form_entry = {
                f"Form {i+1} Action": full_action_url,
                f"Form {i+1} Method": form_method
            }

            # Check for suspicious action URLs
            if not form_action or form_action == '#' or form_action.startswith('javascript:'):
                form_entry[f"Form {i+1} Suspicious Action"] = "Likely handled by JavaScript or points to self (common in phishing)"
            elif urlparse(full_action_url).netloc != urlparse(base_url).netloc:
                form_entry[f"Form {i+1} Suspicious Action"] = "Submitting to external domain (potential phishing)"

            # Check for hidden input fields (optional detail, can be verbose)
            hidden_inputs = form.find_all('input', type='hidden')
            if hidden_inputs:
                hidden_field_names = [inp.get('name') for inp in hidden_inputs if inp.get('name')]
                form_entry[f"Form {i+1} Hidden Fields"] = hidden_field_names if hidden_field_names else "None"

            form_details.append(form_entry)
        clues['form_analysis'] = form_details
    else:
        clues['form_analysis'] = ["No <form> tags found."]

    # --- Input Fields Analysis for Target Data Type Identification ---
    potential_data_targets = set()
    input_field_names = []
    for input_tag in soup.find_all(['input', 'textarea', 'select']):
        name = input_tag.get('name')
        if name:
            input_field_names.append(name.lower())
            # Keywords indicating credential collection
            if any(k in name.lower() for k in ['user', 'email', 'login', 'account', 'username', 'e-mail']):
                potential_data_targets.add("Credentials (Username/Email)")
            if any(k in name.lower() for k in ['pass', 'pwd', 'sandi', 'password', 'kata_sandi']):
                potential_data_targets.add("Credentials (Password)")
            # Keywords indicating financial/payment information
            if any(k in name.lower() for k in ['card', 'cc', 'kartu', 'nomor_kartu', 'credit_card', 'kartu_kredit']):
                potential_data_targets.add("Credit Card/Payment Information")
            if any(k in name.lower() for k in ['cvv', 'cvc', 'kode_verifikasi', 'security_code']):
                potential_data_targets.add("CVV/CVC Credit Card")
            if any(k in name.lower() for k in ['otp', 'token', 'kode_otp', 'one_time_password']):
                potential_data_targets.add("OTP/Verification Code")
            # Keywords indicating personal identification details (specific to Indonesia)
            if any(k in name.lower() for k in ['nik', 'ktp', 'identitas', 'npwp', 'paspor']):
                potential_data_targets.add("NIK/KTP/Personal Identity")
            if any(k in name.lower() for k in ['rekening', 'bank', 'norek', 'nomor_rekening', 'swift']):
                potential_data_targets.add("Bank Account Information")
            if any(k in name.lower() for k in ['pin']):
                potential_data_targets.add("PIN (Personal Identification Number)")
            if any(k in name.lower() for k in ['alamat', 'address', 'jalan', 'kota', 'provinsi']):
                potential_data_targets.add("Personal Address")
            if any(k in name.lower() for k in ['phone', 'telp', 'nomor_telepon']):
                potential_data_targets.add("Phone Number")
    clues['input_field_names_found'] = list(set(input_field_names))
    clues['potential_data_targets'] = list(potential_data_targets)

    # --- External Link Analysis ---
    external_links = []
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        # Also check mailto: and tel: for suspicious contact points
        if href.startswith('http') and urlparse(href).netloc != urlparse(base_url).netloc:
            external_links.append(href)
        elif href.startswith('mailto:') or href.startswith('tel:'):
            external_links.append(href) # Treat as external contact point
    clues['external_links'] = list(set(external_links))

    # --- Keyword Analysis in Text Content (Expanded Keywords) ---
    page_text = soup.get_text().lower()
    phishing_keywords_indicator = []
    common_phishing_phrases = [
        "verify account", "update information", "activate now", "your account has been suspended",
        "prize", "winner", "login now", "click here", "confirm", "urgent",
        "inactive", "block", "important", "this email", "update data",
        "security alert", "suspicious activity", "action required", "immediately",
        "limited time offer", "unauthorized access", "failed login", "billing issue",
        "account review", "upgrade now", "download", "install",
        # Indonesian keywords for broader detection
        "verifikasi akun", "perbarui informasi", "aktivasi sekarang", "akun anda ditangguhkan",
        "hadiah", "pemenang", "login sekarang", "klik di sini", "konfirmasi", "urgent",
        "tidak aktif", "blokir", "penting", "email ini", "update data",
        "peringatan keamanan", "aktivitas mencurigakan", "tindakan diperlukan", "segera",
        "penawaran terbatas", "akses tidak sah", "gagal masuk", "masalah pembayaran",
        "peninjauan akun", "tingkatkan sekarang", "unduh", "pasang",
        "informasi rekening", "data pribadi", "data keuangan", "kartu bank", "bukti transfer"
    ]
    for phrase in common_phishing_phrases:
        if phrase in page_text:
            phishing_keywords_indicator.append(phrase)
    clues['phishing_keywords_in_text'] = phishing_keywords_indicator if phishing_keywords_indicator else "No common phishing keywords found"

    # --- Analyze Redirects in Meta Tags or JavaScript ---
    meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.IGNORECASE)})
    if meta_refresh and 'content' in meta_refresh.attrs:
        content_value = meta_refresh['content']
        match = re.search(r'url=(.*)', content_value, re.IGNORECASE)
        if match:
            clues['meta_refresh_redirect'] = urljoin(base_url, match.group(1))

    js_redirect_clues = []
    for script_tag in soup.find_all('script'):
        if script_tag.string:
            if 'window.location.href' in script_tag.string or 'window.location.replace' in script_tag.string:
                js_redirect_clues.append("Potential JS Redirect detected (static analysis)")
    if js_redirect_clues:
        clues['js_redirect_clues'] = js_redirect_clues

    return clues

def get_domain_ip_info(url):
    clues = {}
    """
    Analyzes domain, IP address, and WHOIS information from a given URL.
    WHOIS data can reveal domain age, registrar, and owner details, which are often suspicious for phishing sites.
    Includes retry mechanism for WHOIS lookup.
    """
    domain_info = {}
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    if not domain:
        domain_info['error'] = "Could not extract domain from URL."
        return domain_info

    # --- WHOIS Lookup with Retry Mechanism ---
    max_retries = 3
    retry_delay = 2 # seconds, will be multiplied for exponential backoff
    whois_data_retrieved = False
    
    for attempt in range(max_retries):
        try:
            print(f"[*] Attempting WHOIS lookup for {domain} (Attempt {attempt + 1}/{max_retries})...")
            w = whois.whois(domain)
            whois_data_retrieved = True
            
            # Ensure attributes exist before accessing
            domain_info['domain_name'] = w.domain_name if w and w.domain_name else "N/A (Data Not Found)"
            
            creation_date = w.creation_date
            if isinstance(creation_date, list): # whois library sometimes returns a list
                creation_date = creation_date[0] if creation_date else None
            
            domain_info['creation_date'] = creation_date if creation_date else "N/A (Data Not Found)"
            domain_info['expiration_date'] = w.expiration_date if w and w.expiration_date else "N/A (Data Not Found)"
            domain_info['registrar'] = w.registrar if w and w.registrar else "N/A (Data Not Found)"
            domain_info['whois_server'] = w.whois_server if w and w.whois_server else "N/A (Data Not Found)"
            domain_info['name_servers'] = w.name_servers if w and w.name_servers else "N/A (Data Not Found)"
            
            # --- Domain Age Check ---
            if creation_date and isinstance(creation_date, datetime):
                age_days = (datetime.now() - creation_date).days
                domain_info['domain_age_days'] = age_days
                if age_days < 90: # Typically, phishing domains are very new (e.g., < 3 months)
                    domain_info['domain_age_suspicion'] = "Very New Domain (Less than 90 days old) - HIGH PHISHING INDICATOR"
                else:
                    domain_info['domain_age_suspicion'] = "Domain appears established (Older than 90 days)"
            else:
                domain_info['domain_age_suspicion'] = "Could not determine domain age (creation date N/A or invalid)"

            # --- Privacy/Proxy Service Check ---
            registrar_lower = str(domain_info['registrar']).lower()
            if any(keyword in registrar_lower for keyword in ['privacy', 'proxy', 'anonymity', 'shield', 'whoisguard', 'domainsbyproxy']):
                domain_info['registrar_privacy_service'] = "Registrar indicates privacy/proxy service (Potential Red Flag)"
            else:
                domain_info['registrar_privacy_service'] = "No obvious privacy/proxy service detected"

            break # Exit retry loop if successful

        except whois.parser.PywhoisError as we_parse:
            domain_info['whois_data'] = f"WHOIS parsing error for {domain}: {we_parse}. Data might be incomplete or malformed."
            print(f"[-] WHOIS parsing error: {we_parse}")
            # Do not retry on parsing error, as it's likely data format issue
            break 
        except whois.whois.WhoisLookupError as wle:
            domain_info['whois_data'] = f"WHOIS lookup failed for {domain}: {wle}. Domain might not exist or WHOIS server is unavailable."
            print(f"[-] WHOIS lookup error: {wle}")
            # This indicates domain not found or server issue, retrying might help
            if attempt < max_retries - 1:
                print(f"[*] Retrying in {retry_delay * (2**attempt)} seconds...")
                time.sleep(retry_delay * (2**attempt))
            else:
                print(f"[-] Max retries reached for WHOIS lookup.")
        except Exception as we:
            domain_info['whois_data'] = f"General WHOIS error for {domain}: {we}. Could be network or server issue."
            print(f"[-] General WHOIS error: {we}")
            if attempt < max_retries - 1:
                print(f"[*] Retrying in {retry_delay * (2**attempt)} seconds...")
                time.sleep(retry_delay * (2**attempt))
            else:
                print(f"[-] Max retries reached for WHOIS lookup.")
    
    if not whois_data_retrieved and 'whois_data' not in domain_info:
        domain_info['whois_data'] = "WHOIS data could not be retrieved after multiple attempts."


    # --- IP Address Lookup ---
    try:
        ip_address = socket.gethostbyname(domain)
        domain_info['ip_address'] = ip_address
    except socket.gaierror:
        domain_info['ip_address'] = "Could not find IP (Unknown hostname or domain does not resolve)"

        domain_info['geoip_info'] = "For GeoIP, integration with external API/DB (e.g., ipinfo.io) is needed."

    return domain_info

def print_results(section_title, data):
    """Helper function for printing results neatly."""
    print(f"\n--- {section_title} ---")
    if data:
        for key, value in data.items():
            # Special handling for form_analysis to print sub-dictionaries neatly
            if key == 'form_analysis' and isinstance(value, list):
                print(f"  - {key}:")
                for form_entry in value:
                    print(f"    --- Form Entry ---")
                    for sub_key, sub_value in form_entry.items():
                        print(f"      - {sub_key}: {sub_value}")
            if key == 'form_analysis': # Check if the key is 'form_analysis'
                if isinstance(value, list): # If it's a list (expected format for details)
                    print(f"  - {key}:")
                    for form_entry in value:
                        if isinstance(form_entry, dict): # Ensure each entry is a dict
                            print(f"    --- Form Entry ---")
                            for sub_key, sub_value in form_entry.items():
                                print(f"      - {sub_key}: {sub_value}")
                        else: # Handle cases where it's not a dict, e.g., "No <form> tags found." string
                            print(f"    - {form_entry}")
                else: # If form_analysis is not a list (e.g., a string like "No <form> tags found.")
                    print(f"  - {key}: {value}")
            elif isinstance(value, list) and not value:
                print(f"  - {key}: [] (Empty)")
            elif isinstance(value, list):
                print(f"  - {key}:")
                for item in value:
                    print(f"    - {item}")
            else:
                print(f"  - {key}: {value}")
    else:
        print("  No data found.")

def print_banner():
    """Prints the tool's ASCII art banner."""
    print(r"""
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
    """)


def run_gb_phishing_analyzer():
    """
    Main function for running the phishing analysis tool.
    It operates in a continuous loop, allowing multiple URL analyses until the user quits.
    """
    while True: # Main loop to keep the tool running
        print_banner() # Print banner at the start of each new loop iteration

        phishing_url = input("Enter the Phishing URL to analyze (Example: https://malicious.com) or type 'exit' to quit: ")
        if phishing_url.lower() == 'exit':
            print("Exiting GB Phishing Analyzer. Good bye!")
            break # Exit the loop if the user types 'exit'
        
        if not phishing_url:
            print("[-] URL cannot be empty. Please try again.")
            continue # Go back to the start of the loop if URL is empty

        print(f"\n[+] Starting analysis for: {phishing_url}")

        html_content = get_html_content(phishing_url) # Using the basic get_html_content
        if not html_content:
            print("\n[-] Analysis terminated due to failure to retrieve HTML content.")
            input("Press Enter to continue to main menu...") # Wait for user input before returning to main menu
            continue # Go back to the start of the loop

        html_analysis_results = analyze_html_clues(html_content, phishing_url)
        print_results("HTML Content & Phishing Element Analysis", html_analysis_results)
        domain_ip_results = get_domain_ip_info(phishing_url)
        print_results("Domain & IP Analysis", domain_ip_results)

        print("\n[+] Core Analysis Complete.")
        
        print("\n[!] Important Warning:")
        print("    - Always perform this analysis in a secure environment (VM/Sandbox), and try using VPN !")
        print("    - These results are preliminary findings; confirmation and manual analysis are still required.")
        
        # Return to the tool's main prompt
        input("\nPress Enter to analyze another URL or type 'exit' to quit...")
        # The user can type 'exit' here as well, but the main 'exit' check is at the beginning of the loop.
        # If they just press Enter, the loop will continue.

if __name__ == "__main__":
    run_gb_phishing_analyzer()

