"""
Configuration settings for WTP
"""


DEFAULT_KEYWORD_CONFIG = {
    'keyword_categories': {
        'common_phishing': {'file': 'common_phishing.txt', 'weight': 15, 'description': 'Common phishing phrases'},
        'financial': {'file': 'financial.txt', 'weight': 10, 'description': 'Financial-related terms'},
        'urgency_pressure': {'file': 'urgency_pressure.txt', 'weight': 12, 'description': 'Urgency and pressure tactics'},
        'security_scams': {'file': 'security_scams.txt', 'weight': 20, 'description': 'Security-related scams'},
        'too_good_to_be_true': {'file': 'too_good_to_be_true.txt', 'weight': 8, 'description': 'Too good to be true offers'},
        'adult_gaming': {'file': 'adult_gaming.txt', 'weight': 5, 'description': 'Adult/Gaming content'}
    },
    'settings': {
        'case_sensitive': False,
        'match_whole_words': True,
        'max_matches_per_category': 5
    }
}


RISK_THRESHOLDS = {
    'LOW': 40,
    'MEDIUM': 60,
    'HIGH': 80,
    'CRITICAL': 100
}


FORCE_COLOR = True


DEFAULT_KEYWORDS_DIR = "keywords"