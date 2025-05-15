"""
Email authentication (SPF, DKIM, DMARC) analysis
"""

import re
import ipaddress


def analyze_authentication(headers):
    """Analyze SPF, DKIM, and DMARC results."""
    auth_results = {}
    
    
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


def extract_ips_from_headers(headers):
    """Extract IP addresses from email headers."""
    ips = []
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    
    for header, value in headers.items():
        if header.lower().startswith('received'):
            found_ips = ip_pattern.findall(value)
            for ip in found_ips:
                try:
                    
                    ipaddress.ip_address(ip)
                    
                    if not ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip).is_loopback:
                        ips.append(ip)
                except:
                    pass
    
    return list(set(ips))


def check_phishing_simulation(headers):
    """Check if email might be a phishing simulation."""
    has_received_headers = any(header.lower().startswith('received') for header in headers.keys())
    has_antispam_headers = any('microsoft-antispam' in header.lower() for header in headers.keys())
    has_authentication_results = any('authentication-results' in header.lower() for header in headers.keys())
    
    return has_antispam_headers and not has_received_headers and not has_authentication_results