"""
Main email analysis logic
"""

from core.parsers import create_parser
from core.keyword_analyzer import analyze_email_content
from core.risk_scorer import get_risk_score
from detectors.character_detector import detect_and_flag_suspicious_chars, detect_character_spacing_evasion
from detectors.url_detector import analyze_urls
from detectors.auth_detector import analyze_authentication, extract_ips_from_headers, check_phishing_simulation
from detectors.business_context import analyze_business_context


class EmailAnalyzer:
    """Main email analyzer that coordinates all analysis components."""
    
    def __init__(self):
        """Initialize the email analyzer."""
        pass
    
    def analyze_file(self, file_path):
        """Analyze an email file (MSG or EML) and return comprehensive results."""
        
        parser = create_parser(file_path)
        parsed_data = parser.parse(file_path)
        
        
        subject = parsed_data['subject']
        body = parsed_data['body']
        headers = parsed_data['headers']
        urls = parsed_data['urls']
        domains = parsed_data['domains']
        
        
        result = {
            'subject': subject,
            'from': parsed_data['from'],
            'to': parsed_data['to'],
            'cc': parsed_data['cc'],
            'headers': headers,
            'urls': urls,
            'domains': domains,
            'body': body
        }
        
        
        if 'date' in parsed_data and parsed_data['date']:
            result['date'] = parsed_data['date']
        
        
        if 'detected_encoding' in parsed_data and parsed_data['detected_encoding']:
            result['detected_encoding'] = parsed_data['detected_encoding']
        
        
        flagged_body, suspicious_chars, encoding_issues = detect_and_flag_suspicious_chars(body)
        spacing_issues = detect_character_spacing_evasion(body)
        
        
        flagged_subject, subject_suspicious_chars, subject_encoding_issues = detect_and_flag_suspicious_chars(subject)
        
        result.update({
            'flagged_body': flagged_body,
            'flagged_subject': flagged_subject,
            'suspicious_chars': suspicious_chars + subject_suspicious_chars,
            'encoding_issues': encoding_issues + subject_encoding_issues,
            'spacing_issues': spacing_issues
        })
        
        
        result['external_ips'] = extract_ips_from_headers(headers)
        result['auth_results'] = analyze_authentication(headers)
        result['url_analysis'] = analyze_urls(urls)
        result['content_analysis'] = analyze_email_content(subject, body)
        
        
        result['is_phishing_sim'] = check_phishing_simulation(headers)
        
        
        business_context = analyze_business_context(subject, body, urls, domains, headers)
        result['business_context'] = business_context
        
        
        risk_score, risk_factors = get_risk_score(result, business_context)
        result['risk_score'] = risk_score
        result['risk_factors'] = risk_factors
        
        return result