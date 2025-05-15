"""
Business context detection for legitimate services
"""

import re
from urllib.parse import urlparse


def is_legitimate_marketing_service(headers, domains):
    """Detect legitimate marketing services like SendInBlue, Mailchimp, etc."""
    marketing_services = [
        'sendibm1.com',  
        'sendinblue.com',
        'mailchimp.com',
        'constantcontact.com',
        'campaignmonitor.com',
        'aweber.com',
        'getresponse.com',
        'convertkit.com',
        'activecampaign.com',
        'hubspot.com'
    ]
    
    
    for domain in domains:
        for service in marketing_services:
            if service in domain.lower():
                return True, service
    
    
    for header, value in headers.items():
        if header.lower() in ['x-mailer', 'x-sender', 'list-unsubscribe']:
            for service in marketing_services:
                if service in value.lower():
                    return True, service
    
    return False, None


def detect_business_indicators(subject, body):
    """Detect business context indicators in email content."""
    business_indicators = [
        r'unsubscribe',
        r'manage\s+preferences',
        r'privacy\s+policy',
        r'terms\s+of\s+service',
        r'contact\s+us',
        r'view\s+in\s+browser',
        r'mailing\s+address',
        r'©\s+\d{4}',  
    ]
    
    text = f"{subject} {body}".lower()
    found_indicators = []
    
    for pattern in business_indicators:
        if re.search(pattern, text, re.IGNORECASE):
            found_indicators.append(pattern)
    
    return found_indicators


def analyze_business_context(subject, body, urls, domains, headers):
    """Analyze business context to determine if email is from legitimate source."""
    result = {
        'is_likely_legitimate': False,
        'legitimacy_score': 0,
        'marketing_service': None,
        'business_indicators': [],
        'factors': []
    }
    
    
    is_marketing, service_name = is_legitimate_marketing_service(headers, domains)
    if is_marketing:
        result['is_likely_legitimate'] = True
        result['marketing_service'] = service_name
        result['legitimacy_score'] += 40
        result['factors'].append(f"Detected marketing service: {service_name}")
    
    
    business_indicators = detect_business_indicators(subject, body)
    if business_indicators:
        result['business_indicators'] = business_indicators
        result['legitimacy_score'] += len(business_indicators) * 5
        result['factors'].append(f"Found {len(business_indicators)} business indicators")
    
    
    if 'unsubscribe' in f"{subject} {body}".lower():
        result['legitimacy_score'] += 10
        result['factors'].append("Contains unsubscribe option")
    
    
    if re.search(r'www\.[a-z]+\.(com|org|net)', f"{subject} {body}", re.IGNORECASE):
        result['legitimacy_score'] += 5
        result['factors'].append("Contains legitimate web domain reference")
    
    
    if result['legitimacy_score'] >= 30:
        result['is_likely_legitimate'] = True
    
    return result