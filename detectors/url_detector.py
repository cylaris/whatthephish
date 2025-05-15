"""
URL analysis and obfuscation detection
"""

import re
import ipaddress
import base64
import mimetypes
from urllib.parse import urlparse, unquote, parse_qs


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


def decode_obfuscated_urls(url):
    """Decode various types of obfuscated URLs."""
    original_url = url
    decoded_urls = [url]
    
    # Try to decode Microsoft SafeLinks first
    url = decode_safelinks(url)
    if url != original_url:
        decoded_urls.append(url)
    
    # Try to decode URL-encoded URLs
    try:
        url_decoded = unquote(url)
        if url_decoded != url:
            decoded_urls.append(url_decoded)
            url = url_decoded
    except:
        pass
    
    # Try to extract nested URLs from query parameters
    try:
        parsed = urlparse(url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for param_name, param_values in query_params.items():
                for param_value in param_values:
                    # Check if parameter value looks like a URL
                    if param_value.startswith(('http://', 'https://', 'www.')):
                        decoded_urls.append(param_value)
                    # Check if parameter value is URL-encoded
                    elif '%' in param_value:
                        try:
                            decoded_param = unquote(param_value)
                            if decoded_param.startswith(('http://', 'https://', 'www.')):
                                decoded_urls.append(decoded_param)
                        except:
                            pass
                    # Check if parameter value is base64 encoded
                    elif len(param_value) > 20 and param_value.replace('=', '').replace('+', '').replace('/', '').isalnum():
                        try:
                            # Add padding if needed
                            missing_padding = len(param_value) % 4
                            if missing_padding:
                                param_value += '=' * (4 - missing_padding)
                            decoded_base64 = base64.b64decode(param_value).decode('utf-8', errors='ignore')
                            if decoded_base64.startswith(('http://', 'https://', 'www.')):
                                decoded_urls.append(decoded_base64)
                        except:
                            pass
    except:
        pass
    
    # Return the most decoded URL and all variations
    return decoded_urls[-1], list(set(decoded_urls))


def analyze_url_content(url):
    """Analyze URL for content type, file extensions, and potential threats."""
    analysis = {
        'file_extensions': [],
        'content_hints': [],
        'obfuscation_level': 0,
        'encoding_layers': 0,
        'suspicious_patterns': []
    }
    
    # Decode the URL and track how many layers of encoding
    final_url, all_urls = decode_obfuscated_urls(url)
    analysis['encoding_layers'] = len(all_urls) - 1
    analysis['obfuscation_level'] = analysis['encoding_layers']
    
    # Analyze the final decoded URL
    parsed = urlparse(final_url)
    path = parsed.path.lower()
    
    # Extract file extensions
    if '.' in path:
        potential_ext = path.split('.')[-1].split('?')[0].split('#')[0]
        if len(potential_ext) <= 5:  # Reasonable file extension length
            analysis['file_extensions'].append(potential_ext)
            
            # Guess content type
            mime_type, _ = mimetypes.guess_type(path)
            if mime_type:
                analysis['content_hints'].append(mime_type)
    
    # Check for suspicious file types
    suspicious_extensions = [
        'exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'js', 'jar',
        'zip', 'rar', '7z', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'
    ]
    
    for ext in analysis['file_extensions']:
        if ext in suspicious_extensions:
            analysis['suspicious_patterns'].append(f"Suspicious file type: .{ext}")
    
    # Check for URL structure obfuscation
    if len(parsed.netloc.split('.')) > 4:
        analysis['obfuscation_level'] += 1
        analysis['suspicious_patterns'].append("Excessive subdomain nesting")
    
    # Check for suspicious URL patterns
    suspicious_url_patterns = [
        (r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', "Direct IP address"),
        (r'bit\.ly|tinyurl|short\.link|ow\.ly|t\.co', "URL shortener"),
        (r'[a-z0-9]{32,}', "Long random string (>32 chars)"),
        (r'%[0-9a-f]{2}', "URL encoding present"),
        (r'[а-я]', "Contains Cyrillic characters"),
        (r'[0-9]{10,}', "Contains long number sequence"),
    ]
    
    for pattern, description in suspicious_url_patterns:
        if re.search(pattern, final_url, re.IGNORECASE):
            analysis['suspicious_patterns'].append(description)
            if description == "URL encoding present":
                analysis['obfuscation_level'] += 1
    
    return analysis, all_urls


def analyze_urls(urls):
    """Analyze URLs for suspicious indicators with enhanced obfuscation detection."""
    url_analysis = {}
    
    for url in urls:
        analysis = {}
        parsed = urlparse(url)
        
        # Enhanced URL analysis
        content_analysis, decoded_variations = analyze_url_content(url)
        analysis.update(content_analysis)
        analysis['decoded_variations'] = decoded_variations
        analysis['final_decoded_url'] = decoded_variations[-1] if decoded_variations else url
        
        # Re-parse the final decoded URL for analysis
        final_parsed = urlparse(analysis['final_decoded_url'])
        
        # Check for IP addresses
        try:
            ipaddress.ip_address(final_parsed.netloc)
            analysis['is_ip'] = True
        except:
            analysis['is_ip'] = False
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit', '.ly', '.gg', '.top', '.click']
        analysis['suspicious_tld'] = any(final_parsed.netloc.endswith(tld) for tld in suspicious_tlds)
        
        # Check URL length
        analysis['length'] = len(url)
        analysis['suspicious_length'] = len(url) > 100
        
        # Enhanced suspicious keyword detection
        suspicious_patterns = [
            'login', 'verify', 'account', 'update', 'secure', 'auth',
            'confirm', 'validate', 'suspend', 'block', 'urgent'
        ]
        analysis['suspicious_keywords'] = [p for p in suspicious_patterns if p in url.lower()]
        
        # Calculate obfuscation score
        analysis['obfuscation_score'] = analysis['obfuscation_level']
        if analysis['encoding_layers'] > 1:
            analysis['obfuscation_score'] += analysis['encoding_layers']
        if len(analysis['suspicious_patterns']) > 0:
            analysis['obfuscation_score'] += len(analysis['suspicious_patterns'])
        
        url_analysis[url] = analysis
    
    return url_analysis


def extract_domain(url):
    """Extract domain from URL."""
    try:
        return urlparse(url).netloc
    except:
        return None