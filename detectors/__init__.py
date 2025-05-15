"""
Detection modules for WTP
"""

from .character_detector import detect_and_flag_suspicious_chars, detect_character_spacing_evasion
from .url_detector import analyze_urls, decode_safelinks, decode_obfuscated_urls, extract_domain
from .auth_detector import analyze_authentication, extract_ips_from_headers, check_phishing_simulation
from .business_context import analyze_business_context

__all__ = [
    'detect_and_flag_suspicious_chars',
    'detect_character_spacing_evasion',
    'analyze_urls',
    'decode_safelinks',
    'decode_obfuscated_urls',
    'extract_domain',
    'analyze_authentication',
    'extract_ips_from_headers',
    'check_phishing_simulation',
    'analyze_business_context'
]