import whois
import requests
from bs4 import BeautifulSoup
import socket
from urllib.parse import urlparse, urljoin
import re
from datetime import datetime
import time 
from tabulate import tabulate
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

# --- CORE FUNCTIONS ---
def clone_website_headless(target_url):
    """
    Visits the URL with a headless browser to get the HTML after JavaScript loads.
    This is a more advanced implementation for cloning modern websites.
    """
    # Configure browser options to run in headless mode (without a GUI).
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    
    # Explicitly set the path to chromedriver to avoid PATH issues.
    # On Kali Linux, the path is often /usr/bin/chromedriver.
    # You might need to change this if your installation is in a different location.
    try:
        driver = webdriver.Chrome(options=chrome_options)
    except WebDriverException as e:
        print(f"[-] ERROR: Failed to initialize chromedriver. Check if it is installed and accessible.")
        print(f"[-] Error message: {e}")
        return None

    try:
        print(f"[+] Using headless browser to clone: {target_url}")
        driver.get(target_url)
        time.sleep(10)  
        wait = WebDriverWait(driver, 15)
        print("[+] Waiting for login elements to appear...")
        wait.until(EC.presence_of_element_located((By.XPATH, "//input[@type='password'] | //input[contains(@name, 'password')]")))
        print("[+] Password element loaded successfully.")

        # Get the fully rendered HTML source code from the browser.
        rendered_html = driver.page_source
        return rendered_html

    except TimeoutException:
        print("[!] Timeout: Password element not found within the specified time. Falling back to the classic method.")
        return None
    except Exception as e:
        print(f"[!] An error occurred while cloning with the headless browser: {e}")
        return None

    finally:
        # Ensure the browser driver session is closed to free up resources.
        if driver:
            driver.quit()
            
# --- CLASSIC FUNCTION TO GET HTML CODE (IF HEADLESS FAILS) ---
def clone_website_classic(target_url):
    """
    Uses requests to get basic HTML.
    This is a fallback method if the headless browser method fails.
    """
    print(f"[+] Trying to clone with the classic method (without JavaScript): {target_url}")
    try:
        response = requests.get(target_url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to clone with the classic method: {e}")
        return None
        
def get_html_content(phishing_url):
    """
    Helper function to get HTML content using the best available method.
    """
    html_content = clone_website_headless(phishing_url)
    if not html_content:
        print("[!] Headless browser method failed. Trying the classic method.")
        html_content = clone_website_classic(phishing_url)
    return html_content

# --- FUNCTION TO ANALYZE AND EXTRACT FORM DATA ---
def analyze_and_extract_form_data(html_content):
    """
    Analyzes the HTML content to find and extract form details.
    """
    print("\n--- Form Analysis ---")
    soup = BeautifulSoup(html_content, 'html.parser')
    forms = soup.find_all('form')

    if not forms:
        print("[!] No <form> tags found in the HTML.")
        return

    print(f"[+] Found {len(forms)} form(s).")
    for i, form in enumerate(forms):
        print(f"\n--- Details for Form {i+1} ---")
        action = form.get('action', 'Not specified')
        method = form.get('method', 'GET').upper()
        
        print(f"Action URL: {action}")
        print(f"Method: {method}")

        input_fields = form.find_all('input')
        print(f"Number of input fields: {len(input_fields)}")
        
        if input_fields:
            for inp in input_fields:
                input_name = inp.get('name', 'N/A')
                input_type = inp.get('type', 'text')
                print(f"  - Input Name: '{input_name}', Type: '{input_type}'")
        else:
            print("  - No input fields found in this form.")

def analyze_html_clues(html_content, phishing_url):
    """
    Analyzes the HTML content for phishing clues.
    """
    clues = {}
    soup = BeautifulSoup(html_content, 'html.parser')
    base_url = phishing_url
    
    clues['url_analysis'] = [{'URL Analysis': phishing_url}]

    form_details = []
    forms = soup.find_all('form')
    if forms:
        for i, form in enumerate(forms):
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET').upper()

            full_action_url = urljoin(base_url, form_action)

            form_entry = {
                f"Form {i+1} Action": full_action_url,
                f"Form {i+1} Method": form_method
            }

            if not form_action or form_action == '#' or form_action.startswith('javascript:'):
                form_entry[f"Form {i+1} Suspicious Action"] = "Likely handled by JavaScript or self-referencing (common in phishing)"
            elif urlparse(full_action_url).netloc != urlparse(base_url).netloc:
                form_entry[f"Form {i+1} Suspicious Action"] = "Submitting to an external domain (potential phishing)"

            hidden_inputs = form.find_all('input', type='hidden')
            if hidden_inputs:
                hidden_field_names = [inp.get('name') for inp in hidden_inputs if inp.get('name')]
                form_entry[f"Form {i+1} Hidden Fields"] = hidden_field_names if hidden_field_names else "None"

            form_details.append(form_entry)
        clues['form_analysis'] = form_details
    else:
        clues['form_analysis'] = ["No <form> tags found."]

    script_clues = []
    for script_tag in soup.find_all('script'):
        if script_tag.string:
            if "eval(" in script_tag.string or "escape(" in script_tag.string:
                script_clues.append("Suspicious JavaScript functions found (e.g., eval, escape).")
    clues['script_analysis'] = script_clues if script_clues else "No suspicious JavaScript functions found"

    potential_data_targets = set()
    input_field_names = []
    for input_tag in soup.find_all(['input', 'textarea', 'select']):
        name = input_tag.get('name')
        if name:
            input_field_names.append(name.lower())
            if any(k in name.lower() for k in ['user', 'email', 'login', 'account', 'username', 'e-mail']):
                potential_data_targets.add("Credentials (Username/Email)")
            if any(k in name.lower() for k in ['pass', 'pwd', 'sandi', 'password', 'kata_sandi']):
                potential_data_targets.add("Credentials (Password)")
            if any(k in name.lower() for k in ['card', 'cc', 'kartu', 'nomor_kartu', 'credit_card', 'kartu_kredit']):
                potential_data_targets.add("Credit Card/Payment Information")
            if any(k in name.lower() for k in ['cvv', 'cvc', 'kode_verifikasi', 'security_code']):
                potential_data_targets.add("Credit Card CVV/CVC")
            if any(k in name.lower() for k in ['otp', 'token', 'kode_otp', 'one_time_password']):
                potential_data_targets.add("OTP/Verification Code")
            if any(k in name.lower() for k in ['nik', 'ktp', 'identitas', 'npwp', 'paspor']):
                potential_data_targets.add("Personal ID/KTP/Passport")
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

    external_links = []
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        if href.startswith('http') and urlparse(href).netloc != urlparse(base_url).netloc:
            external_links.append(href)
        elif href.startswith('mailto:') or href.startswith('tel:'):
            external_links.append(href)
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
        "informasi rekening", "data pribadi", "data keuangan", "kartu bank", "bukti transfer"
    ]
    for phrase in common_phishing_phrases:
        if phrase in page_text:
            phishing_keywords_indicator.append(phrase)
    clues['phishing_keywords_in_text'] = phishing_keywords_indicator if phishing_keywords_indicator else "No common phishing keywords found"

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
                js_redirect_clues.append("Potential JS redirect detected (static analysis)")
    if js_redirect_clues:
        clues['js_redirect_clues'] = js_redirect_clues

    return clues

def get_domain_ip_info(url):
    domain_info = {}
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    if not domain:
        domain_info['error'] = "Unable to extract domain from the URL."
        return domain_info

    max_retries = 5
    retry_delay = 2
    whois_data_retrieved = False

    for attempt in range(max_retries):
        try:
            print(f"[*] Attempting WHOIS lookup for {domain} (Attempt {attempt + 1}/{max_retries})...")
            w = whois.whois(domain)  
            whois_data_retrieved = True

            domain_info['domain_name'] = w.domain_name if w and w.domain_name else "N/A (Data Not Found)"
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            domain_info['creation_date'] = creation_date if creation_date else "N/A (Data Not Found)"
            domain_info['expiration_date'] = w.expiration_date if w and w.expiration_date else "N/A (Data Not Found)"
            domain_info['registrar'] = w.registrar if w and w.registrar else "N/A (Data Not Found)"
            domain_info['whois_server'] = w.whois_server if w and w.whois_server else "N/A (Data Not Found)"
            domain_info['name_servers'] = w.name_servers if w and w.name_servers else "N/A (Data Not Found)"

            if creation_date and isinstance(creation_date, datetime):
                age_days = (datetime.now() - creation_date).days
                domain_info['domain_age_days'] = age_days
                domain_info['domain_age_suspicion'] = "Very New Domain (Less than 90 days) - HIGH PHISHING INDICATOR" if age_days < 90 else "Domain appears to be older than 90 days"
            else:
                domain_info['domain_age_suspicion'] = "Could not determine domain age (creation date N/A or invalid)"

            registrar_lower = str(domain_info['registrar']).lower()
            if any(keyword in registrar_lower for keyword in ['privacy', 'proxy', 'anonymity', 'shield', 'whoisguard', 'domainsbyproxy']):
                domain_info['registrar_privacy_service'] = "Registrar indicates a privacy/proxy service (Potential Red Flag)"
            else:
                domain_info['registrar_privacy_service'] = "No privacy/proxy service detected"

            break
        except Exception as we:
            domain_info['whois_data'] = f"General WHOIS error for {domain}: {we}"
            print(f"[-] General WHOIS error: {we}")
            if attempt < max_retries - 1:
                print(f"[*] Retrying in {retry_delay * (5**attempt)} seconds...")
                time.sleep(retry_delay * (2**attempt))
            else:
                print("[-] Reached maximum attempts for WHOIS lookup.")

    if not whois_data_retrieved and 'whois_data' not in domain_info:
        domain_info['whois_data'] = "WHOIS data could not be retrieved after multiple attempts."
        try:
            ip_address = socket.gethostbyname(domain)
            domain_info['ip_address'] = ip_address
            geoip_info = get_geoip_info(ip_address)
            domain_info['geoip_info'] = geoip_info

            print("\n ── Domain & IP Analysis ──")
            print(f"Domain     : {domain}")
            print(f"IP Address : {ip_address}")

            print("\n ── GeoIP Information ──")
            if geoip_info:
                print(tabulate(geoip_info.items(), headers=["Field", "Value"], tablefmt="fancy_grid"))

        except socket.gaierror:
            domain_info['ip_address'] = "Could not find IP (Hostname unknown)"
            domain_info['geoip_info'] = "GeoIP lookup skipped due to missing IP"


            return domain_info

    
def get_geoip_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()

        if data['status'] != 'success':
            return {"geoip_error": f"API Error: {data.get('message', 'Unknown error')}"}

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
        return {"geoip_error": f"Request failed: {e}"}



def print_results(section_title, data):
    """Helper function to print results neatly."""
    print(f"\n--- {section_title} ---")
    if data:
        for key, value in data.items():
            if key == 'form_analysis' and isinstance(value, list):
                print(f"  - {key}:")
                for form_entry in value:
                    if isinstance(form_entry, dict):
                        print(f"    --- Form Entry ---")
                        for sub_key, sub_value in form_entry.items():
                            print(f"      - {sub_key}: {sub_value}")
                    else:
                        print(f"    - {form_entry}")
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
    """Prints the ASCII art banner of the tool."""
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
    Main function to run the phishing analysis tool.
    It operates in a continuous loop, allowing repeated URL analysis until the user exits.
    """
    while True:
        print_banner()
        phishing_url = input("Enter a Phishing URL to analyze (Example: https://malicious.com) or type 'exit' to quit: ")
        if phishing_url.lower() == 'exit':
            print("Exiting Good Bye Phishing Web. Goodbye!")
            break
        if not phishing_url.startswith("http"):
               phishing_url = "http://" + phishing_url
        if not phishing_url:
            print("[-] URL cannot be empty. Please try again.")
            continue
            print(f"\n[+] Starting analysis for: {phishing_url}")

        html_content = get_html_content(phishing_url) 
        if not html_content:
            print("\n[-] Analysis aborted because HTML content could not be retrieved.")
            input("Press Enter to continue to the main menu...")
            continue

        html_analysis_results = analyze_html_clues(html_content, phishing_url)
        print_results("HTML Content & Phishing Element Analysis", html_analysis_results)
        
        domain_ip_results = get_domain_ip_info(phishing_url)
        print_results("Domain & IP Analysis", domain_ip_results)

        print("\n[+] Core analysis finished.")
        
        print("\n[!] Important Warning:")
        print("    - Always perform this analysis in a secure environment (VM/Sandbox), and consider using a VPN!")
        print("    - These results are initial findings; manual confirmation and further analysis are still required.")
        
        input("\nPress Enter to analyze another URL or type 'exit' to quit...")


if __name__ == "__main__":
    run_gb_phishing_analyzer()


