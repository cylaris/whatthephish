"""
Keyword analysis for phishing detection
"""

import re
import yaml
from pathlib import Path
from utils.colors import Colors
from utils.display import print_info, print_warning, print_error, print_success


class KeywordAnalyzer:
    def __init__(self, keywords_dir="keywords"):
        """Initialize the keyword analyzer with keyword files from a directory."""
        self.keywords_dir = Path(keywords_dir)
        self.keywords = {}
        self.config = {}
        self.load_configuration()
        self.load_keywords()
        self.total_keywords_loaded = 0
    
    def load_configuration(self):
        """Load configuration from config.yaml."""
        config_file = self.keywords_dir / "config.yaml"
        try:
            if config_file.exists():
                with open(config_file, 'r') as f:
                    self.config = yaml.safe_load(f)
                print_info(f"Loaded keyword configuration from {config_file}")
            else:
                print_warning(f"Config file not found at {config_file}, using defaults")
                self._create_default_config()
        except Exception as e:
            print_warning(f"Error loading config: {e}. Using default configuration")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration if none exists."""
        self.config = {
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
    
    def create_default_keyword_files(self):
        """Create default keyword files with example content if they don't exist."""
        default_keywords = {
            'common_phishing.txt': [
                'verify your account', 'update your password', 'action required',
                'suspended account', 'click here', 'login immediately',
                'confirm your identity', 'verify now', 'act now'
            ],
            'financial.txt': [
                'bank account', 'credit card', 'paypal', 'payment',
                'refund', 'invoice', 'transfer', 'wire transfer',
                'bitcoin', 'cryptocurrency'
            ],
            'urgency_pressure.txt': [
                'urgent', 'immediate', 'expires today', 'limited time',
                'act fast', 'hurry', 'expires soon', 'deadline',
                'before it\'s too late', 'last chance'
            ],
            'security_scams.txt': [
                'security alert', 'breach', 'compromised', 'unauthorized access',
                'malware detected', 'virus found', 'security update',
                'antivirus', 'firewall'
            ],
            'too_good_to_be_true.txt': [
                'free money', 'lottery winner', 'inheritance', 'prize',
                'congratulations', 'winner', 'million dollars', 'jackpot'
            ],
            'adult_gaming.txt': [
                'casino', 'gambling', 'poker', 'adult content',
                'dating', 'meet singles', 'webcam'
            ]
        }
        
        # Create keywords directory if it doesn't exist
        self.keywords_dir.mkdir(exist_ok=True)
        
        for filename, keywords in default_keywords.items():
            file_path = self.keywords_dir / filename
            if not file_path.exists():
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('# Default keywords for ' + filename.replace('.txt', '') + '\n')
                    for keyword in keywords:
                        f.write(keyword + '\n')
                print_info(f"Created default keyword file: {filename}")
    
    def load_keywords(self):
        """Load keywords from all configured files."""
        self.total_keywords_loaded = 0
        
        # Create keywords directory and default files if they don't exist
        if not self.keywords_dir.exists():
            print_warning(f"Keywords directory '{self.keywords_dir}' not found. Creating with default files.")
            self.create_default_keyword_files()
        
        for category, config in self.config['keyword_categories'].items():
            keyword_file = self.keywords_dir / config['file']
            try:
                if keyword_file.exists():
                    with open(keyword_file, 'r', encoding='utf-8') as f:
                        keywords = []
                        for line_num, line in enumerate(f.readlines(), 1):
                            line = line.strip()
                            # Skip empty lines and comments
                            if line and not line.startswith('#'):
                                keywords.append(line.lower())
                        
                        self.keywords[category] = keywords
                        self.total_keywords_loaded += len(keywords)
                        print_info(f"Loaded {len(keywords)} keywords from {keyword_file.name}")
                else:
                    print_warning(f"Keyword file not found: {keyword_file}")
                    self.keywords[category] = []
            except Exception as e:
                print_error(f"Error loading keywords from {keyword_file}: {e}")
                self.keywords[category] = []
        
        if self.total_keywords_loaded > 0:
            print_success(f"Total keywords loaded: {self.total_keywords_loaded} from {len(self.keywords)} categories")
        else:
            print_warning("No keywords loaded. Creating default keyword files.")
            self.create_default_keyword_files()
            # Try loading again after creating defaults
            for category, config in self.config['keyword_categories'].items():
                keyword_file = self.keywords_dir / config['file']
                if keyword_file.exists():
                    with open(keyword_file, 'r', encoding='utf-8') as f:
                        keywords = [line.strip().lower() for line in f.readlines() 
                                   if line.strip() and not line.strip().startswith('#')]
                        self.keywords[category] = keywords
                        self.total_keywords_loaded += len(keywords)
    
    def analyze_content(self, subject, body):
        """Analyze subject and body for keyword matches."""
        results = {
            'total_score': 0,
            'categories': {},
            'all_matches': [],
            'summary': [],
            'found_keywords': {},  # Track exactly what keywords were found where
            'highlighted_body': body,  # Body with keywords highlighted
            'highlighted_subject': subject  # Subject with keywords highlighted
        }
        
        # Handle None values
        subject = subject or ""
        body = body or ""
        
        # Keep track of all found keywords for highlighting
        all_found_keywords = []
        
        # Track matches with context
        for category, keywords in self.keywords.items():
            if not keywords:  # Skip empty categories
                continue
                
            category_config = self.config['keyword_categories'].get(category, {})
            weight = category_config.get('weight', 10)
            matches = []
            found_keywords = []
            
            for keyword in keywords:
                search_text = keyword if self.config['settings']['case_sensitive'] else keyword.lower()
                
                # Find in subject and body separately
                subject_matches = 0
                body_matches = 0
                
                if self.config['settings']['match_whole_words']:
                    pattern = r'\b' + re.escape(search_text) + r'\b'
                    subject_matches = len(re.findall(pattern, subject.lower(), re.IGNORECASE))
                    body_matches = len(re.findall(pattern, body.lower(), re.IGNORECASE))
                else:
                    subject_matches = subject.lower().count(search_text)
                    body_matches = body.lower().count(search_text)
                
                total_matches = subject_matches + body_matches
                if total_matches > 0:
                    matches.extend([keyword] * total_matches)
                    found_keywords.append({
                        'keyword': keyword,
                        'subject_count': subject_matches,
                        'body_count': body_matches,
                        'total_count': total_matches
                    })
                    all_found_keywords.append(keyword)
            
            # Apply max matches limit and calculate score
            if matches:
                unique_matches = list(set(matches))
                max_matches = min(len(unique_matches), self.config['settings'].get('max_matches_per_category', 5))
                limited_matches = unique_matches[:max_matches]
                
                # Score based on match frequency and weight
                category_score = len(matches) * weight  # Use total matches, not just unique
                
                results['categories'][category] = {
                    'matches': limited_matches,
                    'count': len(unique_matches),
                    'total_occurrences': len(matches),
                    'score': category_score,
                    'weight': weight,
                    'description': category_config.get('description', category.replace('_', ' ').title())
                }
                results['total_score'] += category_score
                results['all_matches'].extend(limited_matches)
                results['found_keywords'][category] = found_keywords
                
                # Add to summary with context
                summary_parts = []
                if any(k['subject_count'] > 0 for k in found_keywords):
                    subject_keywords = [k['keyword'] for k in found_keywords if k['subject_count'] > 0]
                    summary_parts.append(f"Subject: {len(subject_keywords)} keywords")
                if any(k['body_count'] > 0 for k in found_keywords):
                    body_keywords = [k['keyword'] for k in found_keywords if k['body_count'] > 0]
                    summary_parts.append(f"Body: {len(body_keywords)} keywords")
                
                context = f" ({', '.join(summary_parts)})" if summary_parts else ""
                results['summary'].append(
                    f"{category.replace('_', ' ').title()}: {len(unique_matches)} unique matches ({len(matches)} total){context}"
                )
        
        # Highlight keywords in text
        if all_found_keywords:
            results['highlighted_body'] = self._highlight_keywords(body, all_found_keywords)
            results['highlighted_subject'] = self._highlight_keywords(subject, all_found_keywords)
        
        # Add keyword analysis score to summary
        if results['total_score'] > 0:
            results['summary'].insert(0, f"Total Keyword Score: {results['total_score']}")
        
        return results
    
    def _highlight_keywords(self, text, keywords):
        """Highlight found keywords in text with color."""
        if not text or not keywords:
            return text
        
        # Sort keywords by length (longest first) to avoid partial replacements
        sorted_keywords = sorted(set(keywords), key=len, reverse=True)
        highlighted_text = text
        
        for keyword in sorted_keywords:
            # Create case-insensitive pattern
            if self.config['settings']['match_whole_words']:
                pattern = r'\b' + re.escape(keyword) + r'\b'
            else:
                pattern = re.escape(keyword)
            
            # Replace with highlighted version
            def highlight_match(match):
                return f"{Colors.RED}{Colors.BOLD}[{match.group()}]{Colors.ENDC}"
            
            highlighted_text = re.sub(pattern, highlight_match, highlighted_text, flags=re.IGNORECASE)
        
        return highlighted_text


def analyze_email_content(subject, body):
    """Analyze email content for phishing indicators using keyword analysis."""
    issues = []
    keyword_results = {'total_score': 0, 'categories': {}, 'summary': []}
    
    # Initialize keyword analyzer
    try:
        analyzer = KeywordAnalyzer()
        keyword_results = analyzer.analyze_content(subject, body)
        
        if keyword_results['total_score'] > 0:
            issues.append(f"Keyword Analysis Score: {keyword_results['total_score']}")
            issues.extend(keyword_results['summary'])
        else:
            issues.append("No suspicious keywords detected")
            
    except Exception as e:
        print_error(f"Keyword analysis failed: {e}")
        import traceback
        traceback.print_exc()
    
    return issues, keyword_results