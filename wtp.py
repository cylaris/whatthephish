import argparse
import extract_msg
from extract_msg.exceptions import InvalidFileFormatError
import email.parser
import email.policy
import email
import re
import sys
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup
import os
from datetime import datetime
import ipaddress
import base64
import unicodedata
import chardet

header = r"""
 __    __ _           _  _____ _            ___ _     _     _     
/ / /\ \ \ |__   __ _| |/__   \ |__   ___  / _ \ |__ (_)___| |__  
\ \/  \/ / '_ \ / _ | __|/ /\/ '_ \ / _ \/ /_)/ '_ \| / __| '_ \ 
 \  /\  /| | | | (_| | |_/ /  | | | |  __/ ___/| | | | \__ \ | | |
  \/  \/ |_| |_|\__,_|\__\/   |_| |_|\___\/    |_| |_|_|___/_| |_| v2.0
Lightweight CLI email analysis tool.
------------------------------------------------------
GitHub: https://github.com/cylaris/whatthephish
Made with ❤️ by ntwrite
❗Usage: python3 wtp.py analyze -msg <path> | args: -v (verbose), --no-truncate (no truncation of headers/body)
"""

os.environ['FORCE_COLOR'] = '1'

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'

def setup_argparse():
    parser = argparse.ArgumentParser(description="What's The Phish - A rapid email phishing analysis tool.")
    parser.add_argument('-msg', '--message', required=True, help='Path to the .msg or .eml file to analyse')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--no-truncate', action='store_true', help='Disable truncation of email body and headers')
    return parser.parse_args()

def print_banner(text, color=Colors.BLUE):
    banner_width = 80
    print(f"\n{color}{Colors.BOLD}{'=' * banner_width}")
    print(f"{text:^{banner_width}}")
    print(f"{'=' * banner_width}{Colors.ENDC}")

def print_section(title, color=Colors.GREEN):
    print(f"\n{color}{Colors.BOLD}{title}")
    print(f"{'-' * len(title)}{Colors.ENDC}")

def print_subsection(title, color=Colors.CYAN):
    print(f"\n{color}{Colors.BOLD}  {title}{Colors.ENDC}")

def print_key_value(key, value, color=Colors.BLUE, indent=0):
    spaces = " " * indent
    if isinstance(value, str) and '\n' in value:
        lines = value.split('\n')
        print(f"{spaces}{color}{key}:{Colors.ENDC}")
        for line in lines:
            print(f"{spaces}  {line}")
    else:
        print(f"{spaces}{color}{key}:{Colors.ENDC} {value}")

def print_warning(text):
    print(f"{Colors.YELLOW}{Colors.BOLD}⚠️  {text}{Colors.ENDC}")

def print_error(text):
    print(f"{Colors.RED}{Colors.BOLD}❌ {text}{Colors.ENDC}")

def print_info(text):
    print(f"{Colors.BLUE}{Colors.BOLD}ℹ️  {text}{Colors.ENDC}")

def print_success(text):
    print(f"{Colors.GREEN}{Colors.BOLD}✅ {text}{Colors.ENDC}")

def detect_and_flag_suspicious_chars(text):
    """Detect suspicious characters and mixed scripts that could be evasion attempts."""
    if not text:
        return text, []
    
    issues = []
    flagged_text = text
    suspicious_chars = []
    
    # Common suspicious characters used for evasion
    suspicious_unicode_ranges = [
        (0x0100, 0x017F, "Latin Extended-A"),  # Lookalikes
        (0x0180, 0x024F, "Latin Extended-B"),
        (0x1E00, 0x1EFF, "Latin Extended Additional"),
        (0x2000, 0x206F, "General Punctuation"),  # Invisible chars
        (0x2070, 0x209F, "Superscripts and Subscripts"),
        (0x20A0, 0x20CF, "Currency Symbols"),
        (0x2100, 0x214F, "Letterlike Symbols"),
        (0xFF00, 0xFFEF, "Halfwidth and Fullwidth Forms"),  # Lookalikes
    ]
    
    # Check for invisible/zero-width characters
    invisible_chars = [
        '\u200B',  # Zero Width Space
        '\u200C',  # Zero Width Non-Joiner
        '\u200D',  # Zero Width Joiner
        '\u2060',  # Word Joiner
        '\u3000',  # Ideographic Space
        '\uFEFF',  # Zero Width No-Break Space (BOM)
    ]
    
    # Scan text for suspicious characters
    char_positions = []
    for i, char in enumerate(text):
        code_point = ord(char)
        char_name = unicodedata.name(char, f"UNKNOWN-{code_point}")
        
        # Check if character is in suspicious ranges
        for start, end, range_name in suspicious_unicode_ranges:
            if start <= code_point <= end:
                suspicious_chars.append((char, code_point, char_name, range_name, i))
                char_positions.append(i)
                break
        
        # Check for invisible characters
        if char in invisible_chars:
            suspicious_chars.append((char, code_point, char_name, "Invisible Character", i))
            char_positions.append(i)
            issues.append(f"Invisible character detected: {char_name}")
        
        # Check for homograph attacks (lookalike characters)
        if code_point > 127 and char.isalpha():
            if unicodedata.normalize('NFD', char)[0] in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ':
                suspicious_chars.append((char, code_point, char_name, "Potential Homograph", i))
                char_positions.append(i)
    
    # Create flagged version of text with suspicious chars highlighted
    if char_positions:
        flagged_text = ""
        last_pos = 0
        for pos in char_positions:
            flagged_text += text[last_pos:pos]
            flagged_text += f"{Colors.RED}{Colors.BOLD}[{text[pos]}]{Colors.ENDC}"
            last_pos = pos + 1
        flagged_text += text[last_pos:]
        
        issues.append(f"Found {len(suspicious_chars)} suspicious character(s)")
    
    # Unusual script mixing
    scripts = set()
    for char in text:
        if char.isalpha():
            try:
                script = unicodedata.name(char).split()[0]
                scripts.add(script)
            except:
                pass
    
    if len(scripts) > 1:
        issues.append(f"Multiple scripts detected: {', '.join(scripts)}")
    
    return flagged_text, suspicious_chars, issues

def detect_character_spacing_evasion(text):
    """Detect character spacing evasion techniques."""
    if not text:
        return []
    
    issues = []
    
    # Look for suspicious spacing patterns
    spaced_pattern = re.compile(r'\b[a-zA-Z](\s+[a-zA-Z]){3,}\b')
    spaced_matches = spaced_pattern.findall(text)
    if spaced_matches:
        issues.append(f"Suspicious character spacing detected (potential evasion)")
    
    # Look for mixed spacing with non-breaking spaces
    if '\u00A0' in text:
        issues.append("Non-breaking spaces detected")
    
    # Look for invisible character insertions
    invisibles_count = sum(1 for char in text if unicodedata.category(char) == 'Cf')
    if invisibles_count > 0:
        issues.append(f"Found {invisibles_count} formatting/invisible characters")
    
    return issues

def decode_safelinks(url):
    """Decode Microsoft SafeLinks URLs."""
    parsed = urlparse(url)
    if parsed.netloc.endswith('.protection.outlook.com'):
        query_params = {}
        if parsed.query:
            for q in parsed.query.split('&'):
                if '=' in q:
                    key, value = q.split('=', 1)
                    query_params[key] = value
        if 'url' in query_params:
            return unquote(query_params['url'])
    return url

def extract_ips_from_headers(headers):
    """Extract IP addresses from email headers."""
    ips = []
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    
    for header, value in headers.items():
        if header.lower().startswith('received'):
            found_ips = ip_pattern.findall(value)
            for ip in found_ips:
                try:
                    # Validate IP
                    ipaddress.ip_address(ip)
                    # Exclude private/local IPs
                    if not ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip).is_loopback:
                        ips.append(ip)
                except:
                    pass
    
    return list(set(ips))

def analyze_authentication(headers):
    """Analyze SPF, DKIM, and DMARC results."""
    auth_results = {}
    
    # Look for SPF results
    spf_pattern = re.compile(r'spf=(pass|fail|neutral|softfail|temperror|permerror|none)', re.IGNORECASE)
    dkim_pattern = re.compile(r'dkim=(pass|fail|neutral|temperror|permerror|none)', re.IGNORECASE)
    dmarc_pattern = re.compile(r'dmarc=(pass|fail|none)', re.IGNORECASE)
    
    for header, value in headers.items():
        if header.lower() == 'authentication-results':
            spf_match = spf_pattern.search(value)
            if spf_match:
                auth_results['SPF'] = spf_match.group(1).upper()
                
            dkim_match = dkim_pattern.search(value)
            if dkim_match:
                auth_results['DKIM'] = dkim_match.group(1).upper()
                
            dmarc_match = dmarc_pattern.search(value)
            if dmarc_match:
                auth_results['DMARC'] = dmarc_match.group(1).upper()
    
    return auth_results

def analyze_urls(urls):
    """Analyse URLs for suspicious indicators."""
    url_analysis = {}
    
    for url in urls:
        analysis = {}
        parsed = urlparse(url)
        
        # Check for IP addresses
        try:
            ipaddress.ip_address(parsed.netloc)
            analysis['is_ip'] = True
        except:
            analysis['is_ip'] = False
        
        # Init suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit', '.ly', '.gg']
        for tld in suspicious_tlds:
            if parsed.netloc.endswith(tld):
                analysis['suspicious_tld'] = True
                break
        else:
            analysis['suspicious_tld'] = False
        
        # Check URL length
        analysis['length'] = len(url)
        analysis['suspicious_length'] = len(url) > 100
        
        # Check for suspicious patterns
        suspicious_patterns = [
            'bit.ly', 'tinyurl', 'short.link', 'ow.ly', 't.co',
            'secure', 'login', 'verify', 'account', 'update'
        ]
        analysis['suspicious_keywords'] = [p for p in suspicious_patterns if p in url.lower()]
        
        url_analysis[url] = analysis
    
    return url_analysis

def get_risk_score(result):
    """Calculate a risk score based on various indicators."""
    score = 0
    factors = []
    
    # Authentication failures increase risk
    auth = result.get('auth_results', {})
    if auth.get('SPF') == 'FAIL':
        score += 30
        factors.append("SPF authentication failed")
    if auth.get('DKIM') == 'FAIL':
        score += 20
        factors.append("DKIM authentication failed")
    if auth.get('DMARC') == 'FAIL':
        score += 40
        factors.append("DMARC authentication failed")
    
    # External IPs increase risk slightly
    if result.get('external_ips'):
        score += 10
        factors.append(f"External IPs detected: {len(result['external_ips'])}")
    
    # Suspicious URLs
    url_analysis = result.get('url_analysis', {})
    for url, analysis in url_analysis.items():
        if analysis.get('is_ip'):
            score += 25
            factors.append("URL uses IP address instead of domain")
        if analysis.get('suspicious_tld'):
            score += 15
            factors.append("Suspicious TLD detected")
        if analysis.get('suspicious_length'):
            score += 10
            factors.append("Unusually long URL detected")
        if analysis.get('suspicious_keywords'):
            score += 5 * len(analysis['suspicious_keywords'])
            factors.append(f"Suspicious keywords in URL: {', '.join(analysis['suspicious_keywords'])}")
    
    # Phishing simulation detected
    if result.get('is_phishing_sim'):
        score += 50
        factors.append("Potential phishing simulation detected")
    
    # Character encoding issues
    if result.get('encoding_issues'):
        score += 25
        factors.append("Suspicious character encoding/evasion detected")
    
    # Spacing evasion
    if result.get('spacing_issues'):
        score += 20
        factors.append("Character spacing evasion detected")
    
    return min(score, 100), factors

def analyze_msg_file(file_path):
    """Analyse a .msg file and extract relevant information."""
    try:
        msg = extract_msg.Message(file_path)
        
        subject = msg.subject or "No Subject"
        sender = msg.sender or "Unknown Sender"
        to = msg.to or "Unknown Recipient"
        cc = msg.cc or ""
        
        headers = dict(msg.header) if hasattr(msg, 'header') else {}
        
        body = msg.body or ""
        
        # Extract plain text from HTML if body is HTML
        if body.strip().startswith('<'):
            soup = BeautifulSoup(body, 'html.parser')
            body = soup.get_text(separator='\n', strip=True)
        
        urls = re.findall(r'https?://\S+', body)
        if not urls:
            # Also check HTML body if available
            if hasattr(msg, 'htmlBody') and msg.htmlBody:
                urls.extend(re.findall(r'https?://\S+', msg.htmlBody))
        
        urls = [decode_safelinks(url.rstrip('>')) for url in urls]
        domains = list(set([urlparse(url).netloc for url in urls if url]))
        
        # Analyse character encoding issues
        flagged_body, suspicious_chars, encoding_issues = detect_and_flag_suspicious_chars(body)
        spacing_issues = detect_character_spacing_evasion(body)
        
        # Also check subject for suspicious characters
        flagged_subject, subject_suspicious_chars, subject_encoding_issues = detect_and_flag_suspicious_chars(subject)
        
        # Additional analysis
        external_ips = extract_ips_from_headers(headers)
        auth_results = analyze_authentication(headers)
        url_analysis = analyze_urls(urls)
        
        # Check if this might be a phishing simulation
        is_phishing_sim = check_phishing_simulation(headers)
        
        result = {
            'subject': subject,
            'flagged_subject': flagged_subject,
            'from': sender,
            'to': to,
            'cc': cc,
            'headers': headers,
            'urls': urls,
            'domains': domains,
            'body': body,
            'flagged_body': flagged_body,
            'is_phishing_sim': is_phishing_sim,
            'external_ips': external_ips,
            'auth_results': auth_results,
            'url_analysis': url_analysis,
            'suspicious_chars': suspicious_chars + subject_suspicious_chars,
            'encoding_issues': encoding_issues + subject_encoding_issues,
            'spacing_issues': spacing_issues
        }
        
        # Calculate risk score
        risk_score, risk_factors = get_risk_score(result)
        result['risk_score'] = risk_score
        result['risk_factors'] = risk_factors
        
        return result
        
    except InvalidFileFormatError:
        # If it's not a proper .msg file, it might be an .eml file
        print_info("File doesn't appear to be a proper .msg file. Attempting to process as .eml file...")
        return analyze_eml_file(file_path)

def analyze_eml_file(file_path):
    """Analyze an .eml file and extract relevant information."""
    try:
        # Try to detect encoding first
        with open(file_path, 'rb') as file:
            raw_data = file.read()
            detected_encoding = chardet.detect(raw_data)
            encoding = detected_encoding.get('encoding', 'utf-8')
        
        # Read with detected encoding
        with open(file_path, 'r', encoding=encoding, errors='ignore') as file:
            raw_email = file.read()
        
        # Parse the email
        msg = email.message_from_string(raw_email, policy=email.policy.default)
        
        # Extract headers
        headers = {}
        for header, value in msg.items():
            headers[header] = value
        
        # Extract basic email information
        subject = msg.get('Subject', 'No Subject')
        from_addr = msg.get('From', 'Unknown Sender')
        to_addr = msg.get('To', 'Unknown Recipient')
        cc_addr = msg.get('Cc', '')
        date = msg.get('Date', 'Unknown Date')
        
        # Extract body and URLs
        body, urls, domains = extract_body_and_urls_from_eml(msg)
        
        # Analyse character encoding issues
        flagged_body, suspicious_chars, encoding_issues = detect_and_flag_suspicious_chars(body)
        spacing_issues = detect_character_spacing_evasion(body)
        
        # Also check subject for suspicious characters
        flagged_subject, subject_suspicious_chars, subject_encoding_issues = detect_and_flag_suspicious_chars(subject)
        
        # Additional analysis
        external_ips = extract_ips_from_headers(headers)
        auth_results = analyze_authentication(headers)
        url_analysis = analyze_urls(urls)
        
        # Check if this might be a phishing simulation
        is_phishing_sim = check_phishing_simulation(headers)
        
        result = {
            'subject': subject,
            'flagged_subject': flagged_subject,
            'from': from_addr,
            'to': to_addr,
            'cc': cc_addr,
            'date': date,
            'headers': headers,
            'urls': urls,
            'domains': domains,
            'body': body,
            'flagged_body': flagged_body,
            'is_phishing_sim': is_phishing_sim,
            'external_ips': external_ips,
            'auth_results': auth_results,
            'url_analysis': url_analysis,
            'suspicious_chars': suspicious_chars + subject_suspicious_chars,
            'encoding_issues': encoding_issues + subject_encoding_issues,
            'spacing_issues': spacing_issues,
            'detected_encoding': detected_encoding
        }
        
        # Calculate risk score
        risk_score, risk_factors = get_risk_score(result)
        result['risk_score'] = risk_score
        result['risk_factors'] = risk_factors
        
        return result
        
    except Exception as e:
        print_error(f"Error analysing .eml file: {str(e)}")
        sys.exit(1)

def extract_body_and_urls_from_eml(msg):
    """Extract body content and URLs from an email message object."""
    body = ""
    urls = []
    domains = set()
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            # Skip attachments
            if "attachment" in content_disposition:
                continue
                
            if content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        # Try to detect encoding
                        detected = chardet.detect(payload)
                        encoding = detected.get('encoding', 'utf-8')
                        payload_text = payload.decode(encoding, errors='ignore')
                        body += payload_text + "\n"
                        
                        # Extract URLs from this part
                        part_urls = re.findall(r'https?://\S+', payload_text)
                        urls.extend(part_urls)
                        
                        # Extract domains from URLs
                        for url in part_urls:
                            domain = extract_domain(url)
                            if domain:
                                domains.add(domain)
                except Exception as e:
                    body += f"[Error decoding message part: {str(e)}]\n"
            elif content_type == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        # Try to detect encoding
                        detected = chardet.detect(payload)
                        encoding = detected.get('encoding', 'utf-8')
                        payload_text = payload.decode(encoding, errors='ignore')
                        
                        # Extract URLs from HTML
                        html_urls = re.findall(r'https?://\S+', payload_text)
                        urls.extend(html_urls)
                        
                        # Also check href attributes
                        soup = BeautifulSoup(payload_text, 'html.parser')
                        for link in soup.find_all('a', href=True):
                            if link['href'].startswith(('http://', 'https://')):
                                urls.append(link['href'])
                        
                        # Convert HTML to text for body
                        body += soup.get_text(separator='\n', strip=True) + "\n"
                        
                        # Extract domains from URLs
                        for url in html_urls:
                            domain = extract_domain(url)
                            if domain:
                                domains.add(domain)
                except Exception as e:
                    body += f"[Error decoding HTML part: {str(e)}]\n"
    else:
        # Not multipart, get the payload directly
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                # Try to detect encoding
                detected = chardet.detect(payload)
                encoding = detected.get('encoding', 'utf-8')
                body = payload.decode(encoding, errors='ignore')
                
                # Extract URLs
                urls = re.findall(r'https?://\S+', body)
                
                # Extract domains from URLs
                for url in urls:
                    domain = extract_domain(url)
                    if domain:
                        domains.add(domain)
        except Exception as e:
            body = f"[Error decoding message body: {str(e)}]"
    
    # Decode SafeLinks URLs
    urls = [decode_safelinks(url.rstrip('>')) for url in urls]
    
    return body, list(set(urls)), list(domains)

def extract_domain(url):
    """Extract domain from URL."""
    try:
        return urlparse(url).netloc
    except:
        return None

def check_phishing_simulation(headers):
    """Check if email might be a phishing simulation."""
    has_received_headers = any(header.lower().startswith('received') for header in headers.keys())
    has_antispam_headers = any('microsoft-antispam' in header.lower() for header in headers.keys())
    has_authentication_results = any('authentication-results' in header.lower() for header in headers.keys())
    
    return has_antispam_headers and not has_received_headers and not has_authentication_results

def determine_file_type(file_path):
    """Determine if the file is a .msg or .eml file based on extension."""
    _, ext = os.path.splitext(file_path.lower())
    if ext == '.msg':
        return 'msg'
    elif ext == '.eml':
        return 'eml'
    else:
        print_error(f"Unsupported file type: {ext}. Please provide a .msg or .eml file.")
        sys.exit(1)

def format_body_for_display(body, max_lines=20, no_truncate=False):
    """Format body for display, truncating if necessary."""
    if not body:
        return "No body content found"
    
    if no_truncate:
        return body
    
    lines = body.split('\n')
    if len(lines) > max_lines:
        truncated = '\n'.join(lines[:max_lines])
        truncated += f"\n\n{Colors.YELLOW}[Body truncated - {len(lines) - max_lines} more lines...]{Colors.ENDC}"
        return truncated
    return body

def format_header_for_display(value, max_length=100, no_truncate=False):
    """Format header value for display, truncating if necessary."""
    if not value:
        return ""
    
    if no_truncate:
        return value
        
    if len(value) > max_length:
        return value[:max_length] + "..."
    return value

def main():
    global header
    print(header)
    args = setup_argparse()
    file_path = args.message
    
    if not os.path.exists(file_path):
        print_error(f"File not found: {file_path}")
        sys.exit(1)
    
    file_type = determine_file_type(file_path)
    
    print_info(f"Analysing {file_type.upper()} file: {os.path.basename(file_path)}")
    
    try:
        if file_type == 'msg':
            result = analyze_msg_file(file_path)
        else:  # eml
            result = analyze_eml_file(file_path)
    except Exception as e:
        print_error(f"Error processing file: {str(e)}")
        sys.exit(1)

    # Display results
    print_banner("Email Analysis Report", Colors.BLUE)
    
    # Risk Assessment
    risk_score = result['risk_score']
    if risk_score >= 70:
        print_banner(f"HIGH RISK - Score: {risk_score}/100", Colors.RED)
    elif risk_score >= 40:
        print_banner(f"MEDIUM RISK - Score: {risk_score}/100", Colors.YELLOW)
    else:
        print_banner(f"LOW RISK - Score: {risk_score}/100", Colors.GREEN)
    
    if result['risk_factors']:
        print_subsection("Risk Factors:")
        for factor in result['risk_factors']:
            print(f"  • {factor}")
    
    # Character Encoding Analysis
    if result.get('encoding_issues') or result.get('spacing_issues') or result.get('suspicious_chars'):
        print_section("Character Encoding Analysis", Colors.MAGENTA)
        
        if result.get('detected_encoding'):
            print_key_value("Detected Encoding", f"{result['detected_encoding']['encoding']} (confidence: {result['detected_encoding']['confidence']:.2%})")
        
        if result.get('encoding_issues'):
            print_subsection("Encoding Issues:")
            for issue in result['encoding_issues']:
                print_warning(issue)
        
        if result.get('spacing_issues'):
            print_subsection("Spacing/Evasion Issues:")
            for issue in result['spacing_issues']:
                print_warning(issue)
        
        if result.get('suspicious_chars'):
            print_subsection("Suspicious Characters:")
            char_count = {}
            for char, code_point, char_name, range_name, position in result['suspicious_chars']:
                key = f"{char} (U+{code_point:04X}) - {char_name} [{range_name}]"
                char_count[key] = char_count.get(key, 0) + 1
            
            for char_info, count in sorted(char_count.items()):
                count_str = f" (×{count})" if count > 1 else ""
                print(f"  • {char_info}{count_str}")
    
    # Email Details
    print_section("Email Details")
    print_key_value("Subject", result['flagged_subject'] if result.get('flagged_subject') != result['subject'] else result['subject'])
    print_key_value("From", result['from'])
    print_key_value("To", result['to'])
    if result['cc']:
        print_key_value("CC", result['cc'])
    if 'date' in result:
        print_key_value("Date", result['date'])
    
    # Authentication Results
    print_section("Authentication Results")
    auth_results = result['auth_results']
    if auth_results:
        for auth_type, status in auth_results.items():
            color = Colors.GREEN if status == 'PASS' else Colors.RED
            print_key_value(auth_type, f"{color}{status}{Colors.ENDC}")
    else:
        print_warning("No authentication results found")
    
    # Network Information
    print_section("Network Information")
    if result['external_ips']:
        print_subsection("External IP Addresses:")
        for ip in result['external_ips']:
            print(f"  • {ip}")
    else:
        print("No external IP addresses identified")
    
    # URL Analysis
    print_section("URL Analysis")
    if result['urls']:
        print_subsection("URLs Found:")
        for url in result['urls'][:10]:
            analysis = result['url_analysis'].get(url, {})
            indicators = []
            if analysis.get('is_ip'):
                indicators.append(f"{Colors.RED}IP{Colors.ENDC}")
            if analysis.get('suspicious_tld'):
                indicators.append(f"{Colors.YELLOW}SUSPICIOUS TLD{Colors.ENDC}")
            if analysis.get('suspicious_length'):
                indicators.append(f"{Colors.YELLOW}LONG{Colors.ENDC}")
            if analysis.get('suspicious_keywords'):
                indicators.append(f"{Colors.YELLOW}KEYWORDS{Colors.ENDC}")
            
            indicator_str = f" [{', '.join(indicators)}]" if indicators else ""
            print(f"  • {url}{indicator_str}")
        
        if len(result['urls']) > 10:
            print(f"  ... and {len(result['urls']) - 10} more URLs")
        
        print_subsection("Unique Domains:")
        for domain in result['domains'][:10]:  # Limit to first 10 domains
            print(f"  • {domain}")
        if len(result['domains']) > 10:
            print(f"  ... and {len(result['domains']) - 10} more domains")
    else:
        print("No URLs found")
    
    # Phishing Simulation Detection
    if result['is_phishing_sim']:
        print_section("Phishing Simulation Detection", Colors.YELLOW)
        print_warning("This email contains Microsoft anti-spam headers but lacks typical email routing headers.")
        print_warning("It may be part of a phishing awareness exercise.")
    
    # Headers (if verbose)
    if args.verbose:
        print_section("Email Headers")
        important_headers = ['Received', 'Authentication-Results', 'X-Microsoft-Antispam', 'X-MS-Exchange-Organization', 'Return-Path']
        for header, value in sorted(result['headers'].items()):
            if any(h.lower() in header.lower() for h in important_headers):
                print_key_value(header, format_header_for_display(value, no_truncate=args.no_truncate), Colors.YELLOW)
    
    # Email Body (truncated unless --no-truncate)
    print_section("Email Body (with suspicious chars flagged)")
    flagged_body = result.get('flagged_body', result['body'])
    print(format_body_for_display(flagged_body, no_truncate=args.no_truncate))
    
    print_banner("Analysis Complete", Colors.BLUE)
    
    # Summary
    print_section("Summary", Colors.CYAN)
    print(f"Total URLs: {len(result['urls'])}")
    print(f"Unique Domains: {len(result['domains'])}")
    print(f"External IPs: {len(result['external_ips'])}")
    print(f"Suspicious Characters: {len(result.get('suspicious_chars', []))}")
    print(f"Risk Score: {risk_score}/100")
    
    # Add note about truncation
    if not args.no_truncate:
        print(f"\n{Colors.CYAN}💡 Use --no-truncate to see full content without truncation{Colors.ENDC}")

if __name__ == "__main__":
    main()