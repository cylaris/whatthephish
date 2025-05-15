"""
Confidence scoring for risk assessment
"""

from enum import Enum


class ConfidenceLevel(Enum):
    """Confidence levels for risk assessment."""
    VERY_LOW = (0.2, "Very Low")
    LOW = (0.4, "Low")
    MEDIUM = (0.6, "Medium")
    HIGH = (0.8, "High")
    VERY_HIGH = (0.95, "Very High")
    
    def __init__(self, value, label):
        self.score = value  
        self.label = label


class ConfidenceCalculator:
    """Calculate confidence scores for different risk indicators."""
    
    @staticmethod
    def calculate_keyword_confidence(keyword_results, business_context):
        """Calculate confidence for keyword analysis."""
        total_score = keyword_results.get('total_score', 0)
        categories = keyword_results.get('categories', {})
        
        
        confidence = 0.7
        
        
        if len(categories) >= 3:
            confidence += 0.15  
        elif len(categories) == 1:
            confidence -= 0.1   
        
        
        if business_context and business_context.get('is_likely_legitimate'):
            
            confidence *= 0.7
            
            confidence = max(confidence, 0.3)
        
        
        if total_score > 100:
            confidence = min(confidence + 0.15, 0.95)
        
        return confidence
    
    @staticmethod
    def calculate_auth_confidence(auth_results, business_context):
        """Calculate confidence for authentication analysis."""
        
        failures = [k for k, v in auth_results.items() if v == 'FAIL']
        passes = [k for k, v in auth_results.items() if v == 'PASS']
        
        if len(failures) >= 2:
            return 0.9  
        elif len(failures) == 1:
            return 0.75
        elif len(passes) >= 2 and business_context and business_context.get('is_likely_legitimate'):
            
            return 0.3
        else:
            return 0.6
    
    @staticmethod
    def calculate_character_confidence(suspicious_chars, encoding_issues, business_context):
        """Calculate confidence for character encoding analysis."""
        invisible_count = len([c for c in suspicious_chars if c[3] == "Invisible Character"])
        homograph_count = len([c for c in suspicious_chars if c[3] == "Potential Homograph"])
        
        
        confidence = 0.6
        
        
        if homograph_count > 0:
            confidence += 0.2  
        
        if invisible_count > 0:
            
            if business_context and business_context.get('is_likely_legitimate'):
                
                if invisible_count < 100:
                    confidence = 0.3
                elif invisible_count < 500:
                    confidence = 0.5
                else:
                    confidence = 0.7  
            else:
                
                confidence += min(invisible_count / 100 * 0.3, 0.3)
        
        return min(confidence, 0.95)
    
    @staticmethod
    def calculate_url_confidence(url_analysis, domains, business_context):
        """Calculate confidence for URL analysis."""
        obfuscated_count = sum(1 for analysis in url_analysis.values() 
                              if analysis.get('obfuscation_score', 0) > 2)
        ip_count = sum(1 for analysis in url_analysis.values() if analysis.get('is_ip'))
        
        
        confidence = 0.7
        
        
        if ip_count > 0:
            confidence = 0.9
        
        
        if obfuscated_count > 0:
            if business_context and business_context.get('is_likely_legitimate'):
                
                confidence = 0.4 + (obfuscated_count / 10) * 0.3
            else:
                confidence += min(obfuscated_count / 10 * 0.2, 0.2)
        
        return min(confidence, 0.95)
    
    @staticmethod
    def calculate_overall_confidence(risk_components, business_context):
        """Calculate overall confidence for the risk assessment."""
        keyword_conf = ConfidenceCalculator.calculate_keyword_confidence(
            risk_components.get('keyword_results', {}), business_context)
        auth_conf = ConfidenceCalculator.calculate_auth_confidence(
            risk_components.get('auth_results', {}), business_context)
        char_conf = ConfidenceCalculator.calculate_character_confidence(
            risk_components.get('suspicious_chars', []), 
            risk_components.get('encoding_issues', []), business_context)
        url_conf = ConfidenceCalculator.calculate_url_confidence(
            risk_components.get('url_analysis', {}), 
            risk_components.get('domains', []), business_context)
        
        
        weights = {
            'keyword': 0.25,
            'auth': 0.25,
            'character': 0.25,
            'url': 0.25
        }
        
        overall_confidence = (
            keyword_conf * weights['keyword'] +
            auth_conf * weights['auth'] +
            char_conf * weights['character'] +
            url_conf * weights['url']
        )
        
        
        threat_vectors = sum([
            1 if risk_components.get('keyword_results', {}).get('total_score', 0) > 0 else 0,
            1 if any(v == 'FAIL' for v in risk_components.get('auth_results', {}).values()) else 0,
            1 if len(risk_components.get('suspicious_chars', [])) > 10 else 0,
            1 if any(a.get('obfuscation_score', 0) > 2 for a in risk_components.get('url_analysis', {}).values()) else 0
        ])
        
        
        if threat_vectors >= 3:
            overall_confidence = min(overall_confidence + 0.1, 0.95)
        elif threat_vectors == 1:
            overall_confidence = max(overall_confidence - 0.1, 0.2)
        
        return overall_confidence
    
    @staticmethod
    def get_confidence_level(confidence_score):
        """Convert confidence score to confidence level enum."""
        if confidence_score >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif confidence_score >= 0.75:
            return ConfidenceLevel.HIGH
        elif confidence_score >= 0.55:
            return ConfidenceLevel.MEDIUM
        elif confidence_score >= 0.35:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW


def calculate_risk_confidence(result, business_context):
    """Main function to calculate risk confidence."""
    calculator = ConfidenceCalculator()
    
    
    risk_components = {
        'keyword_results': result.get('content_analysis', ([], {}))[1],
        'auth_results': result.get('auth_results', {}),
        'suspicious_chars': result.get('suspicious_chars', []),
        'encoding_issues': result.get('encoding_issues', []),
        'url_analysis': result.get('url_analysis', {}),
        'domains': result.get('domains', [])
    }
    
    
    confidence_score = calculator.calculate_overall_confidence(risk_components, business_context)
    confidence_level = calculator.get_confidence_level(confidence_score)
    
    return {
        'confidence_score': confidence_score,
        'confidence_level': confidence_level,
        'component_confidences': {
            'keyword': calculator.calculate_keyword_confidence(
                risk_components['keyword_results'], business_context),
            'authentication': calculator.calculate_auth_confidence(
                risk_components['auth_results'], business_context),
            'character': calculator.calculate_character_confidence(
                risk_components['suspicious_chars'], risk_components['encoding_issues'], business_context),
            'url': calculator.calculate_url_confidence(
                risk_components['url_analysis'], risk_components['domains'], business_context)
        }
    }