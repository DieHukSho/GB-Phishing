import whois
import requests
from bs4 import BeautifulSoup
import socket
from urllib.parse import urlparse, urljoin
import re
from datetime import datetime
import time
import sys # For colored output
import os # To check for files
from tabulate import tabulate
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By


# --- ANSI COLOR CODES ---
# Define colors for better readability of the output.
# These codes work in most modern terminals.
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'

# --- CORE FUNCTIONS ---
def clone_website_headless(target_url):
    """
    Visits the URL with a headless browser to get the HTML after JavaScript loads.
    This is a more advanced implementation for cloning modern websites.
    """
    print(f"{CYAN}{BOLD}[+] Using a headless browser to clone: {target_url}{RESET}")
    # Configure browser options to run in headless mode (without a GUI).
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    # Add a User-Agent to make the headless browser appear more like a real browser.
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    DRIVER_PATH = "./chromedriver-linux64/chromedriver"

    driver = None
    try:
        print(f"[+] Using a headless browser to clone: {target_url}")
        
        # Initialize the service with the driver path
        service = webdriver.chrome.service.Service(executable_path=DRIVER_PATH)
        driver = webdriver.Chrome(service=service, options=chrome_options)

        driver.get(target_url)

        # Wait for the login form elements to appear.
        wait = WebDriverWait(driver, 15) # Increase wait time to 15 seconds
        print("[+] Waiting for login elements to appear...")
        # Try to wait for an input element with name 'password' or type 'password'
        # This is more general than waiting for a "Login" button, which may not exist on all pages.
        wait.until(EC.presence_of_element_located((By.XPATH, "//input[@type='password'] | //input[contains(@name, 'password')]")))
        print("[+] Password element loaded successfully.")
    
        # Get the fully rendered HTML source code from the browser.
        rendered_html = driver.page_source
        return rendered_html
 
    # --- END USER-SPECIFIC PATH CONFIGURATION ---

    # The code below seems to be a duplicate of the above try block with some modifications.
    # It has been moved into the main try/except structure for proper flow.
    except TimeoutException:
        print(f"{YELLOW}[!] Timeout: The website took too long to load. Falling back to the classic method.{RESET}")
        return None
    except Exception as e:
        print(f"{RED}[!] An error occurred while cloning with the headless browser: {e}{RESET}")
        return None

    finally:
        if driver:
            driver.quit()
            
# --- CLASSIC FUNCTION TO GET HTML CODE (IF HEADLESS FAILS) ---
def clone_website_classic(target_url):
    """
    Uses requests to get basic HTML.
    This is a fallback method if the headless browser method fails.
    """
    print(f"{CYAN}[+] Trying to clone with the classic method (without JavaScript): {target_url}{RESET}")
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(target_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"{RED}[!] Failed to clone with the classic method: {e}{RESET}")
        return None
        
def get_html_content(phishing_url):
    """
    Helper function to get HTML content using the best available method.
    """
    html_content = clone_website_headless(phishing_url)
    if not html_content:
        print(f"{YELLOW}[!] Headless browser method failed. Attempting classic method.{RESET}")
        html_content = clone_website_classic(phishing_url)
    return html_content

# --- FUNCTION TO ANALYZE AND EXTRACT FORM DATA ---
def analyze_html_clues(html_content, phishing_url):
    """
    Analyzes the HTML content for various phishing clues.
    """
    clues = {}
    soup = BeautifulSoup(html_content, 'html.parser')
    base_url = phishing_url
    
    clues['url_analysis'] = [{'URL': phishing_url}]

    form_details = []
    forms = soup.find_all('form')
    if forms:
        for i, form in enumerate(forms):
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET').upper()
            full_action_url = urljoin(base_url, form_action)

            form_entry = {
                f"Form {i+1} Action URL": full_action_url,
                f"Form {i+1} Method": form_method
            }

            if not form_action or form_action == '#' or form_action.startswith('javascript:'):
                form_entry[f"Form {i+1} Suspicious Action"] = f"{YELLOW}Likely handled by JavaScript or self-referencing (common in phishing){RESET}"
            elif urlparse(full_action_url).netloc != urlparse(base_url).netloc:
                form_entry[f"Form {i+1} Suspicious Action"] = f"{RED}Submitting to an external domain (high potential phishing){RESET}"

            hidden_inputs = form.find_all('input', type='hidden')
            if hidden_inputs:
                hidden_field_names = [inp.get('name') for inp in hidden_inputs if inp.get('name')]
                form_entry[f"Form {i+1} Hidden Fields"] = hidden_field_names if hidden_field_names else "None"

            form_details.append(form_entry)
        clues['form_analysis'] = form_details
    else:
        clues['form_analysis'] = [f"{GREEN}No <form> tags were found.{RESET}"]

    script_clues = []
    for script_tag in soup.find_all('script'):
        if script_tag.string:
            if "eval(" in script_tag.string or "escape(" in script_tag.string:
                script_clues.append(f"{RED}Suspicious JavaScript functions found (e.g., eval, escape).{RESET}")
    clues['script_analysis'] = script_clues if script_clues else f"{GREEN}No suspicious JavaScript functions found.{RESET}"

    potential_data_targets = set()
    input_field_names = []
    for input_tag in soup.find_all(['input', 'textarea', 'select']):
        name = input_tag.get('name')
        if name:
            input_field_names.append(name.lower())
            if any(k in name.lower() for k in ['user', 'email', 'login', 'account', 'username', 'e-mail']):
                potential_data_targets.add(f"{YELLOW}Credentials (Username/Email){RESET}")
            if any(k in name.lower() for k in ['pass', 'pwd', 'sandi', 'password', 'kata_sandi']):
                potential_data_targets.add(f"{RED}Credentials (Password){RESET}")
            if any(k in name.lower() for k in ['card', 'cc', 'kartu', 'nomor_kartu', 'credit_card', 'kartu_kredit']):
                potential_data_targets.add(f"{RED}Credit Card/Payment Information{RESET}")
            if any(k in name.lower() for k in ['cvv', 'cvc', 'kode_verifikasi', 'security_code']):
                potential_data_targets.add(f"{RED}Credit Card CVV/CVC{RESET}")
            if any(k in name.lower() for k in ['otp', 'token', 'kode_otp', 'one_time_password']):
                potential_data_targets.add(f"{RED}OTP/Verification Code{RESET}")
            if any(k in name.lower() for k in ['nik', 'ktp', 'identitas', 'npwp', 'paspor']):
                potential_data_targets.add(f"{RED}Personal ID/KTP/Passport{RESET}")
            if any(k in name.lower() for k in ['rekening', 'bank', 'norek', 'nomor_rekening', 'swift']):
                potential_data_targets.add(f"{RED}Bank Account Information{RESET}")
            if any(k in name.lower() for k in ['pin']):
                potential_data_targets.add(f"{RED}PIN (Personal Identification Number){RESET}")
            if any(k in name.lower() for k in ['alamat', 'address', 'jalan', 'kota', 'provinsi']):
                potential_data_targets.add(f"{YELLOW}Personal Address{RESET}")
            if any(k in name.lower() for k in ['phone', 'telp', 'nomor_telepon']):
                potential_data_targets.add(f"{YELLOW}Phone Number{RESET}")
    clues['input_field_names_found'] = list(set(input_field_names))
    clues['potential_data_targets'] = list(potential_data_targets)

    external_links = []
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        if href.startswith('http') and urlparse(href).netloc != urlparse(base_url).netloc:
            external_links.append(f"{RED}{href}{RESET}")
        elif href.startswith('mailto:') or href.startswith('tel:'):
            external_links.append(f"{YELLOW}{href}{RESET}")
    clues['external_links'] = list(set(external_links))

    page_text = soup.get_text().lower()
    phishing_keywords_indicator = []
    common_phishing_phrases = [
        "verify account", "update information", "activate now", "your account has been suspended",
        "prize", "winner", "login now", "click here", "confirm", "urgent",
        "inactive", "block", "important", "this email", "update data",
        "security alert", "suspicious activity", "action required", "immediately",
        "limited time offer", "unauthorized access", "failed login", "billing issue",
        "account review", "upgrade now", "download", "install",
        "verifikasi akun", "perbarui informasi", "aktivasi sekarang", "akun anda ditangguhkan",
        "hadiah", "pemenang", "login sekarang", "klik di sini", "konfirmasi", "urgent",
        "tidak aktif", "blokir", "penting", "email ini", "update data",
        "peringatan keamanan", "aktivitas mencurigakan", "tindakan diperlukan", "segera",
        "penawaran terbatas", "akses tidak sah", "gagal masuk", "masalah pembayaran",
        "peninjauan akun", "tingkatkan sekarang", "unduh", "pasang",
        "informasi rekening", "data pribadi", "data keuangan", "kartu bank", "bukti transfer",
        "kewajiban anda", "tindakan darurat", "penangguhan layanan", "hadiah tunai", "anda terpilih",
        "pendaftaran ulang", "konfirmasi identitas", "klik tautan ini", "akun diblokir",
        "peringatan sistem", "pembaruan keamanan", "login sekarang juga", "segera bertindak",
        "urgent action", "account locked", "service suspended", "identity verification",
        "click this link", "your account has been selected", "cash prize", "re-register",
        "system alert", "security update", "login now", "act now",
        "your personal details", "bank transfer proof"
    ]
    for phrase in common_phishing_phrases:
        if phrase in page_text:
            phishing_keywords_indicator.append(phrase)
    clues['phishing_keywords_in_text'] = phishing_keywords_indicator if phishing_keywords_indicator else "No common phishing keywords found."

    meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.IGNORECASE)})
    if meta_refresh and 'content' in meta_refresh.attrs:
        content_value = meta_refresh['content']
        match = re.search(r'url=(.*)', content_value, re.IGNORECASE)
        if match:
            clues['meta_refresh_redirect'] = f"{RED}{urljoin(base_url, match.group(1))}{RESET}"

    js_redirect_clues = []
    for script_tag in soup.find_all('script'):
        if script_tag.string:
            if 'window.location.href' in script_tag.string or 'window.location.replace' in script_tag.string:
                js_redirect_clues.append(f"{YELLOW}Potential JS Redirect detected (static analysis){RESET}")
    if js_redirect_clues:
        clues['js_redirect_clues'] = js_redirect_clues

    return clues

def get_domain_ip_info(url):
    """
    Analyzes the domain, IP address, and WHOIS information of the given URL.
    This function consolidates all domain-related information.
    """
    domain_info = {}
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    if not domain:
        domain_info['error'] = "Could not extract domain from URL."
        return domain_info

    max_retries = 3
    retry_delay = 2
    whois_data_retrieved = False
    
    for attempt in range(max_retries):
        try:
            print(f"{MAGENTA}[*] Attempting WHOIS lookup for {domain} (Attempt {attempt + 1}/{max_retries})...{RESET}")
            w = whois.whois(domain)
            whois_data_retrieved = True
            
            domain_info['domain_name'] = w.domain_name if w and w.domain_name else "N/A (Data Not Found)"
            
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0] if creation_date else None
            
            domain_info['creation_date'] = creation_date if creation_date else "N/A (Data Not Found)"
            domain_info['expiration_date'] = w.expiration_date if w and w.expiration_date else "N/A (Data Not Found)"
            domain_info['registrar'] = w.registrar if w and w.registrar else "N/A (Data Not Found)"
            domain_info['whois_server'] = w.whois_server if w and w.whois_server else "N/A (Data Not Found)"
            domain_info['name_servers'] = w.name_servers if w and w.name_servers else "N/A (Data Not Found)"
            
            if creation_date and isinstance(creation_date, datetime):
                age_days = (datetime.now() - creation_date).days
                domain_info['domain_age_days'] = age_days
                if age_days < 90:
                    domain_info['domain_age_suspicion'] = f"{RED}Very New Domain (Less than 90 days) - HIGH PHISHING INDICATOR{RESET}"
                else:
                    domain_info['domain_age_suspicion'] = f"{GREEN}Domain appears established (More than 90 days){RESET}"
            else:
                domain_info['domain_age_suspicion'] = f"{YELLOW}Could not determine domain age (creation date N/A or invalid){RESET}"

            registrar_lower = str(domain_info['registrar']).lower()
            if any(keyword in registrar_lower for keyword in ['privacy', 'proxy', 'anonymity', 'shield', 'whoisguard', 'domainsbyproxy']):
                domain_info['registrar_privacy_service'] = f"{YELLOW}Registrar indicates a privacy/proxy service (Potential Red Flag){RESET}"
            else:
                domain_info['registrar_privacy_service'] = f"{GREEN}No privacy/proxy service detected{RESET}"

            break

        except whois.parser.PywhoisError as we_parse:
            domain_info['whois_data'] = f"{YELLOW}WHOIS parsing error for {domain}: {we_parse}. Data may be incomplete.{RESET}"
            break 
        except whois.whois.WhoisLookupError as wle:
            domain_info['whois_data'] = f"{RED}WHOIS lookup failed for {domain}: {wle}. Domain may not exist or the WHOIS server is unavailable.{RESET}"
            if attempt < max_retries - 1:
                print(f"{YELLOW}[*] Retrying in {retry_delay * (2**attempt)} seconds...{RESET}")
                time.sleep(retry_delay * (2**attempt))
            else:
                print(f"{RED}[-] Reached maximum attempts for WHOIS lookup.{RESET}")
        except Exception as we:
            domain_info['whois_data'] = f"{RED}General WHOIS error for {domain}: {we}. May be a network or server issue.{RESET}"
            if attempt < max_retries - 1:
                print(f"{YELLOW}[*] Retrying in {retry_delay * (2**attempt)} seconds...{RESET}")
                time.sleep(retry_delay * (2**attempt))
            else:
                print(f"{RED}[-] Reached maximum attempts for WHOIS lookup.{RESET}")
    
    if not whois_data_retrieved and 'whois_data' not in domain_info:
        domain_info['whois_data'] = f"{RED}WHOIS data could not be retrieved after multiple attempts.{RESET}"

    try:
        ip_address = socket.gethostbyname(domain)
        domain_info['ip_address'] = ip_address
        geoip_info = get_geoip_info(ip_address)
        domain_info['geoip_info'] = geoip_info

    except socket.gaierror:
        domain_info['ip_address'] = f"{RED}Could not find IP (Hostname unknown or domain could not be resolved){RESET}"
        domain_info['geoip_info'] = f"{YELLOW}GeoIP lookup skipped because no IP address was found.{RESET}"
    except Exception as e:
        print(f"{RED}[-] An unexpected error occurred during IP/GeoIP lookup: {e}{RESET}")
        domain_info['ip_address'] = f"{RED}N/A{RESET}"
        domain_info['geoip_info'] = f"{RED}N/A{RESET}"

    return domain_info

def get_geoip_info(ip):
    """
    Fetches GeoIP information for a given IP address.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()

        if data['status'] != 'success':
            return {f"{RED}geoip_error{RESET}": f"API Error: {data.get('message', 'Unknown error')}"}

        return {
            "Country": data.get("country"),
            "Region": data.get("regionName"),
            "City": data.get("city"),
            "ISP": data.get("isp"),
            "Organization": data.get("org"),
            "ASN": data.get("as"),
            "Timezone": data.get("timezone"),
            "Latitude": data.get("lat"),
            "Longitude": data.get("lon")
        }

    except Exception as e:
        return {f"{RED}geoip_error{RESET}": f"Request Failed: {e}"}

def print_results(section_title, data):
    """Helper function to print results neatly with colors."""
    print(f"\n{CYAN}--- {section_title} ---{RESET}")
    if data:
        for key, value in data.items():
            if key == 'form_analysis' and isinstance(value, list):
                print(f"  - {BOLD}{key}{RESET}:")
                for form_entry in value:
                    if isinstance(form_entry, dict):
                        print(f"    {MAGENTA}--- Form Entry ---{RESET}")
                        for sub_key, sub_value in form_entry.items():
                            print(f"      - {BOLD}{sub_key}{RESET}: {sub_value}")
                    else:
                        print(f"    - {form_entry}")
            elif key == 'geoip_info' and isinstance(value, dict):
                print(f"  - {BOLD}GeoIP Information{RESET}:")
                if 'geoip_error' in value:
                    print(f"    - {value['geoip_error']}")
                else:
                    table_data = [[f"{BOLD}{k}{RESET}", v] for k, v in value.items()]
                    print(tabulate(table_data, headers=["Field", "Value"], tablefmt="fancy_grid"))
            elif isinstance(value, list) and not value:
                print(f"  - {BOLD}{key}{RESET}: [] (Empty)")
            elif isinstance(value, list):
                print(f"  - {BOLD}{key}{RESET}:")
                for item in value:
                    print(f"    - {item}")
            else:
                print(f"  - {BOLD}{key}{RESET}: {value}")
    else:
        print(f"  {YELLOW}No data found.{RESET}")

def generate_summary(html_results, domain_results):
    """Generates a concise summary of the analysis findings."""
    print(f"\n{MAGENTA}--- Analysis Summary ---{RESET}")
    score = 0
    risk_level = "LOW"
    summary_text = []

    # Check HTML clues
    if html_results.get('phishing_keywords_in_text') and html_results['phishing_keywords_in_text'] != "No common phishing keywords found.":
        score += 3
        summary_text.append(f"{RED}* HIGH: Common phishing keywords were found in the page text.{RESET}")
    if html_results.get('potential_data_targets'):
        score += 2
        summary_text.append(f"{RED}* HIGH: The page contains input fields for sensitive data (e.g., passwords, credit cards).{RESET}")
    if html_results.get('external_links'):
        score += 1
        summary_text.append(f"{YELLOW}* MEDIUM: External links were found, which could lead to malicious sites.{RESET}")
    if html_results.get('form_analysis') and html_results['form_analysis'] != [f"{GREEN}No <form> tags were found.{RESET}"]:
        for form in html_results['form_analysis']:
            if "Suspicious Action" in list(form.keys()):
                if "external" in form[list(form.keys())[2]].lower():
                    score += 3
                    summary_text.append(f"{RED}* HIGH: A form is configured to submit data to an external, suspicious domain.{RESET}")
                else:
                    score += 2
                    summary_text.append(f"{YELLOW}* MEDIUM: A form has a suspicious action (e.g., self-referencing or JavaScript-handled).{RESET}")

    # Check domain clues
    if domain_results.get('domain_age_suspicion') and "Very New Domain" in domain_results['domain_age_suspicion']:
        score += 3
        summary_text.append(f"{RED}* HIGH: The domain is very new (less than 90 days), a common phishing indicator.{RESET}")
    if domain_results.get('registrar_privacy_service') and "privacy/proxy" in domain_results['registrar_privacy_service']:
        score += 1
        summary_text.append(f"{YELLOW}* MEDIUM: The domain uses a privacy protection service, which can be a red flag.{RESET}")

    if score >= 5:
        risk_level = f"{RED}{BOLD}HIGH{RESET}"
    elif score >= 2:
        risk_level = f"{YELLOW}{BOLD}MEDIUM{RESET}"
    else:
        risk_level = f"{GREEN}{BOLD}LOW{RESET}"
        summary_text.append(f"{GREEN}* The analysis found no major phishing indicators.{RESET}")

    print(f"Overall Phishing Risk Level: {risk_level}")
    print("Key Findings:")
    for item in summary_text:
        print(item)


def print_banner():
    """Prints the ASCII art banner of the tool."""
    print(CYAN + BOLD + r"""
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
""" + RESET)


def run_gb_phishing_analyzer():
    """
    Main function to run the phishing analysis tool.
    It operates in a continuous loop, allowing repeated URL analysis until the user exits.
    """
    while True:
        print_banner()
        phishing_url = input(f"{BOLD}Enter a Phishing URL to analyze (Example: https://malicious.com) or type 'exit' to quit:{RESET} ")
        if phishing_url.lower() == 'exit':
            print(f"{GREEN}Exiting Good Bye Phishing Web. Goodbye!{RESET}")
            break
        if not phishing_url:
            print(f"{RED}[-] URL cannot be empty. Please try again.{RESET}")
            continue
        
        if not phishing_url.startswith("http"):
            phishing_url = "http://" + phishing_url
        
        print(f"\n{CYAN}[+] Starting analysis for: {phishing_url}{RESET}")

        html_content = get_html_content(phishing_url)
        if not html_content:
            print(f"\n{RED}[-] Analysis canceled because HTML content could not be retrieved.{RESET}")
            input(f"{YELLOW}Press Enter to continue to the main menu...{RESET}")
            continue

        html_analysis_results = analyze_html_clues(html_content, phishing_url)
        print_results("HTML Content & Phishing Element Analysis", html_analysis_results)
        
        domain_ip_results = get_domain_ip_info(phishing_url)
        print_results("Domain & IP Analysis", domain_ip_results)

        print(f"\n{GREEN}[+] Core analysis complete.{RESET}")
        
        generate_summary(html_analysis_results, domain_ip_results)

        print(f"\n{YELLOW}[!] Important Warning:{RESET}")
        print("    - Always perform this analysis in a secure environment (VM/Sandbox), and consider using a VPN!")
        print("    - These results are initial findings; manual confirmation and further analysis are still required.")
        
        input(f"\n{BOLD}Press Enter to analyze another URL or type 'exit' to quit...{RESET}")


if __name__ == "__main__":
    run_gb_phishing_analyzer()
