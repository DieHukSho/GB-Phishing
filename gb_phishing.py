import requests
from bs4 import BeautifulSoup
import whois
import socket
from urllib.parse import urlparse, urljoin
import re
import json # Required for VirusTotal

# --- CORE FUNCTIONS ---

def get_html_content(url):
    """
    Retrieves HTML content from a given URL using basic requests (no JavaScript rendering).
    Handles common request errors.
    """
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True, verify=True)
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"[-] Error retrieving web content from {url}: {e}")
        return None

def analyze_html_clues(html_content, base_url):
    """
    Analyzes HTML content for common phishing clues such as form actions,
    input field names, external links, and suspicious keywords.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    clues = {}

    # --- Form Action URLs ---
    # Identifies where form data might be submitted, a key indicator for phishing.
    form_submission_urls = []
    forms = soup.find_all('form')
    if forms:
        for form in forms:
            action = form.get('action')
            if action:
                full_action_url = urljoin(base_url, action) # Resolve relative URLs
                form_submission_urls.append(full_action_url)
            else:
                form_submission_urls.append(base_url) # If no action, defaults to current page
        clues['form_submission_urls'] = list(set(form_submission_urls)) # Remove duplicates
    else:
        clues['form_submission_urls'] = ["No <form> tags found."]

    # --- Input Fields Analysis for Target Data Type Identification ---
    # Detects common input field names to infer what type of data the page is trying to collect.
    potential_data_targets = set()
    input_field_names = []
    for input_tag in soup.find_all(['input', 'textarea', 'select']):
        name = input_tag.get('name')
        if name:
            input_field_names.append(name.lower())
            # Keywords indicating credential collection
            if any(k in name.lower() for k in ['user', 'email', 'login', 'account']):
                potential_data_targets.add("Credentials (Username/Email)")
            if any(k in name.lower() for k in ['pass', 'pwd', 'sandi']):
                potential_data_targets.add("Credentials (Password)")
            # Keywords indicating financial/payment information
            if any(k in name.lower() for k in ['card', 'cc', 'kartu', 'nomor_kartu']):
                potential_data_targets.add("Credit Card/Payment Information")
            if any(k in name.lower() for k in ['cvv', 'cvc', 'kode_verifikasi']):
                potential_data_targets.add("CVV/CVC Credit Card")
            if any(k in name.lower() for k in ['otp', 'token', 'kode_otp']):
                potential_data_targets.add("OTP/Verification Code")
            # Keywords indicating personal identification details (specific to Indonesia)
            if any(k in name.lower() for k in ['nik', 'ktp', 'identitas']):
                potential_data_targets.add("NIK/KTP/Personal Identity")
            if any(k in name.lower() for k in ['rekening', 'bank', 'norek']):
                potential_data_targets.add("Bank Account Information")
    clues['input_field_names_found'] = list(set(input_field_names))
    clues['potential_data_targets'] = list(potential_data_targets)

    # --- External Link Analysis ---
    # Identifies links pointing to domains different from the base URL.
    # Phishing sites often link to legitimate pages (e.g., privacy policy) to appear credible.
    external_links = []
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        if href.startswith('http') and urlparse(href).netloc != urlparse(base_url).netloc:
            external_links.append(href)
    clues['external_links'] = list(set(external_links))

    # --- Keyword Analysis in Text Content ---
    # Scans the page's text for common phishing phrases that aim to create urgency or deception.
    page_text = soup.get_text().lower()
    phishing_keywords_indicator = []
    common_phishing_phrases = [
        "verify account", "update information", "activate now", "your account has been suspended",
        "prize", "winner", "login now", "click here", "confirm", "urgent",
        "inactive", "block", "important", "this email", "update data",
        # Indonesian keywords for broader detection
        "verifikasi akun", "perbarui informasi", "aktivasi sekarang", "akun anda ditangguhkan",
        "hadiah", "pemenang", "login sekarang", "klik di sini", "konfirmasi", "urgent",
        "tidak aktif", "blokir", "penting", "email ini", "update data"
    ]
    for phrase in common_phishing_phrases:
        if phrase in page_text:
            phishing_keywords_indicator.append(phrase)
    clues['phishing_keywords_in_text'] = phishing_keywords_indicator if phishing_keywords_indicator else "No common phishing keywords found"

    # --- Analyze Redirects in Meta Tags or JavaScript ---
    # Checks for static HTML meta refresh tags.
    meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.IGNORECASE)})
    if meta_refresh and 'content' in meta_refresh.attrs:
        content_value = meta_refresh['content']
        match = re.search(r'url=(.*)', content_value, re.IGNORECASE)
        if match:
            clues['meta_refresh_redirect'] = urljoin(base_url, match.group(1))

    # Checks for basic JavaScript redirects (static analysis only).
    js_redirect_clues = []
    for script_tag in soup.find_all('script'):
        if script_tag.string:
            if 'window.location.href' in script_tag.string or 'window.location.replace' in script_tag.string:
                js_redirect_clues.append("Potential JS Redirect detected (static analysis)")
    if js_redirect_clues:
        clues['js_redirect_clues'] = js_redirect_clues

    return clues

def get_domain_ip_info(url):
    """
    Analyzes domain, IP address, and WHOIS information from a given URL.
    WHOIS data can reveal domain age, registrar, and owner details, which are often suspicious for phishing sites.
    """
    domain_info = {}
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        if domain:
            try:
                w = whois.whois(domain)
                domain_info['domain_name'] = w.domain_name
                domain_info['creation_date'] = w.creation_date
                domain_info['expiration_date'] = w.expiration_date
                domain_info['registrar'] = w.registrar
                domain_info['whois_server'] = w.whois_server
                domain_info['name_servers'] = w.name_servers
            except Exception as we:
                domain_info['whois_data'] = f"Error WHOIS lookup: {we}"

            try:
                ip_address = socket.gethostbyname(domain)
                domain_info['ip_address'] = ip_address
            except socket.gaierror:
                domain_info['ip_address'] = "Could not find IP (Unknown hostname)"

            # Note: For GeoIP, integration with an external API/DB (e.g., ipinfo.io) is needed.
            domain_info['geoip_info'] = "For GeoIP, integration with external API/DB (e.g., ipinfo.io) is needed."

        else:
            domain_info['error'] = "Could not extract domain from URL."

    except Exception as e:
        domain_info['error'] = f"Error analyzing domain/IP: {e}"
    return domain_info

def virustotal_url_scan(url, api_key):
    """
    Submits a URL to VirusTotal for analysis and retrieves results.
    Requires a valid VirusTotal API key.
    """
    if not api_key: # Check if API Key is empty
        print("\n[!] VirusTotal API Key not provided. Skipping VirusTotal scan.")
        return None

    print(f"\n[+] Submitting URL to VirusTotal: {url}")
    vt_url_submit = "https://www.virustotal.com/api/v3/urls"
    vt_url_report = "https://www.virustotal.com/api/v3/analyses/"

    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {"url": url}

    try:
        # Submit URL for analysis
        response = requests.post(vt_url_submit, headers=headers, data=data)
        response.raise_for_status() # Will raise HTTPError for 4xx/5xx status codes
        result = response.json()
        analysis_id = result['data']['id']
        print(f"[+] URL submitted to VirusTotal. Analysis ID: {analysis_id}")
        print("[+] Waiting for VirusTotal analysis results (this may take a moment)...")

        # Poll for results
        max_retries = 10
        import time # Import time here as it's only used within this function
        for i in range(max_retries):
            report_response = requests.get(f"{vt_url_report}{analysis_id}", headers=headers)
            report_response.raise_for_status()
            report_data = report_response.json()
            status = report_data['data']['attributes']['status']

            if status == "completed":
                stats = report_data['data']['attributes']['stats']
                print(f"[+] VirusTotal Analysis Complete:")
                print(f"    - Malicious: {stats.get('malicious', 0)}")
                print(f"    - Suspicious: {stats.get('suspicious', 0)}")
                print(f"    - Harmless: {stats.get('harmless', 0)}")
                print(f"    - Undetected: {stats.get('undetected', 0)}")
                print(f"    - Timeout: {stats.get('timeout', 0)}")
                return stats
            elif status == "queued" or status == "not_found":
                print(f"    Still {status}... Retrying in 5 seconds ({i+1}/{max_retries})")
                time.sleep(5)
            else:
                print(f"    Unknown status: {status}")
                break
        print("[-] VirusTotal analysis timed out or failed to complete.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[-] Error with VirusTotal API: {e}")
        return None
    except json.JSONDecodeError:
        print("[-] Error decoding JSON response from VirusTotal. Check API Key or response format.")
        return None
    except Exception as e:
        print(f"[-] An unexpected error occurred during VirusTotal scan: {e}")
        return None

def print_results(section_title, data):
    """Helper function for printing results neatly."""
    print(f"\n--- {section_title} ---")
    if data:
        for key, value in data.items():
            if isinstance(value, list) and not value:
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
    print("  ▄████  ▒█████   ▒█████  ▓█████▄     ▄▄▄▄   ▓██   ██▓▓█████     ██▓███   ██░ ██  ██▓  ██████  ██▓ ███▄    █   ▄████     █     █░▓█████  ▄▄▄▄   ")
    print(" ██▒ ▀█▒▒██▒  ██▒▒██▒  ██▒▒██▀ ██▌   ▓█████▄  ▒██  ██▒▓█   ▀    ▓██░  ██▒▓██░ ██▒▓██▒▒██    ▒ ▓██▒ ██ ▀█   █  ██▒ ▀█▒   ▓█░ █ ░█░▓█   ▀ ▓█████▄ ")
    print("▒██░▄▄▄░▒██░  ██▒▒██░  ██▒░██   █▌   ▒██▒ ▄██  ▒██ ██░▒███      ▓██░ ██▓▒▒██▀▀██░▒██▒░ ▓██▄   ▒██▒▓██  ▀█ ██▒▒██░▄▄▄░   ▒█░ █ ░█ ▒███   ▒██▒ ▄██")
    print("░▓█  ██▓▒██   ██░▒██   ██░░▓█▄   ▌   ▒██░█▀    ░ ▐██▓░▒▓█  ▄    ▒██▄█▓▒ ▒░▓█ ░██ ░██░  ▒   ██▒░██░▓██▒  ▐▌██▒░▓█  ██▓   ░█░ █ ░█ ▒▓█  ▄ ▒██░█▀  ")
    print("░▒▓███▀▒░ ████▓▒░░ ████▓▒░░▒████▓    ░▓█  ▀█▓  ░ ██▒▓░░▒████▒   ▒██▒ ░  ░░▓█▒░██▓░██░▒██████▒▒░██░▒██░   ▓██░░▒▓███▀▒   ░░██▒██▓ ░▒████▒░▓█  ▀█▓")
    print(" ░▒   ▒ ░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▒▓  ▒    ░▒▓███▀▒   ██▒▒▒ ░░ ▒░ ░   ░▓▒░ ░  ░ ▒ ░░▒░▒░▓  ▒ ▒▓▒ ▒ ░░▓  ░ ▒░   ▒ ▒  ░▒   ▒    ░ ▓░▒ ▒  ░░ ▒░ ░░▒▓███▀▒")
    print("  ░   ░   ░ ▒ ▒░   ░ ▒ ▒░  ░ ▒  ▒    ▒░▒   ░  ▓██ ░▒░  ░ ░  ░   ░▒ ░      ▒ ░▒░ ░ ▒ ░░ ░▒  ░ ░ ▒ ░░ ░░   ░ ▒░  ░   ░      ▒ ░ ░   ░ ░  ░▒░▒   ░ ")
    print("░ ░   ░ ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░  ░     ░    ░  ▒ ▒ ░░     ░      ░░        ░  ░░ ░ ▒ ░░  ░  ░   ▒ ░   ░   ░ ░ ░ ░   ░      ░   ░     ░    ░    ░ ")
    print("      ░     ░ ░      ░ ░     ░        ░       ░ ░        ░  ░             ░  ░  ░ ░        ░   ░           ░       ░        ░       ░  ░ ░      ")
    print("                           ░               ░  ░ ░                                                                                             ░ ")
    print("        [+] GB Phishing (Good Bye Phishing) Analyzer by [DieHukShoo] [+]\n")

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
        
        # --- Option for Third-Party Application Features with Manual API Key Input ---
        perform_vt_scan = input("\nDo you want to perform an additional VirusTotal URL scan? (y/n): ").lower()
        if perform_vt_scan == 'y':
            api_key_input = input("Enter your VirusTotal API Key (press Enter to skip): ")
            if not api_key_input:
                print("[!] No VirusTotal API Key provided. Skipping VirusTotal scan for this session.")
            else:
                virustotal_results = virustotal_url_scan(phishing_url, api_key_input)
                if virustotal_results:
                    print_results("VirusTotal URL Scan Results", virustotal_results)
        elif perform_vt_scan != 'n': # If input is neither 'y' nor 'n', inform the user
            print("[!] Invalid input. Skipping VirusTotal scan.")


        print("\n[!] Important Warning:")
        print("    - Always perform this analysis in a secure environment (VM/Sandbox)!")
        print("    - These results are preliminary findings; confirmation and manual analysis are still required.")
        
        # Return to the tool's main prompt
        input("\nPress Enter to analyze another URL or type 'exit' to quit...")
        # The user can type 'exit' here as well, but the main 'exit' check is at the beginning of the loop.
        # If they just press Enter, the loop will continue.

if __name__ == "__main__":
    run_gb_phishing_analyzer()
