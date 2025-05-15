"""
Risk scoring calculation with business context awareness
"""


def get_risk_score(result, business_context=None):
    """Calculate a risk score based on various indicators with business context awareness."""
    score = 0
    score_breakdown = []
    correlations = []
    critical_indicators = []
    
    
    keyword_results = result.get('content_analysis', ([], {}))[1]
    keyword_score = keyword_results.get('total_score', 0)
    suspicious_chars = result.get('suspicious_chars', [])
    invisible_count = len([c for c in suspicious_chars if c[3] == "Invisible Character"])
    homograph_count = len([c for c in suspicious_chars if c[3] == "Potential Homograph"])
    encoding_issues = result.get('encoding_issues', [])
    has_script_mixing = any("Multiple scripts" in issue for issue in encoding_issues)
    has_cyrillic = any("CYRILLIC" in issue for issue in encoding_issues)
    auth_results = result.get('auth_results', {})
    
    
    is_legitimate_service = business_context and business_context.get('is_likely_legitimate', False) if business_context else False
    legitimacy_score = business_context.get('legitimacy_score', 0) if business_context else 0
    
    
    url_analysis = result.get('url_analysis', {})
    obfuscated_urls = sum(1 for analysis in url_analysis.values() if analysis.get('obfuscation_score', 0) > 2)
    highly_obfuscated = sum(1 for analysis in url_analysis.values() if analysis.get('obfuscation_score', 0) > 5)
    ip_urls = sum(1 for analysis in url_analysis.values() if analysis.get('is_ip'))
    suspicious_file_urls = sum(1 for analysis in url_analysis.values() if any('exe' in ext or 'scr' in ext for ext in analysis.get('file_extensions', [])))
    
    
    if keyword_score > 0:
        normalized_keyword_score = min(keyword_score * 0.9, 35)
        
        
        if is_legitimate_service and legitimacy_score > 50:
            
            adjusted_score = normalized_keyword_score * 0.6
            correlations.append(f"📧 Business context: Keyword score reduced ({normalized_keyword_score:.1f} → {adjusted_score:.1f})")
            normalized_keyword_score = adjusted_score
        
        score += normalized_keyword_score
        score_breakdown.append(f"📝 Keyword Analysis: +{normalized_keyword_score:.1f} points")
        
        
        urgency_categories = ['urgency_pressure', 'common_phishing']
        has_urgency = any(cat in keyword_results.get('categories', {}) for cat in urgency_categories)
        if has_urgency and not is_legitimate_service:
            critical_indicators.append("High-urgency phishing language detected")
    
    
    auth_score = 0
    auth_failures = []
    auth_passes = []
    
    if auth_results.get('SPF') == 'FAIL':
        auth_score += 12
        auth_failures.append('SPF')
    elif auth_results.get('SPF') == 'PASS':
        auth_passes.append('SPF')
    
    if auth_results.get('DKIM') == 'FAIL':
        auth_score += 10
        auth_failures.append('DKIM')
    elif auth_results.get('DKIM') == 'PASS':
        auth_passes.append('DKIM')
    
    if auth_results.get('DMARC') == 'FAIL':
        auth_score += 18
        auth_failures.append('DMARC')
    elif auth_results.get('DMARC') == 'PASS':
        auth_passes.append('DMARC')
    
    
    if len(auth_passes) >= 2 and (keyword_score > 0 or obfuscated_urls > 0 or invisible_count > 0):
        if not is_legitimate_service:
            auth_score += 5
            correlations.append("🚨 SOPHISTICATED SPOOF: Valid auth + phishing indicators")
        else:
            
            service_name = business_context.get('marketing_service', 'Unknown') if business_context else 'Unknown'
            correlations.append(f"📧 Legitimate service with tracking: {service_name}")
    
    if auth_score > 0:
        score += auth_score
        score_breakdown.append(f"🔐 Authentication Issues: +{auth_score} points")
    
    
    char_score = 0
    
    if invisible_count > 0:
        
        base_char_score = min(invisible_count * 0.4, 20)
        
        
        if is_legitimate_service:
            
            if invisible_count < 100:
                
                adjusted_score = base_char_score * 0.2
                correlations.append(f"📧 Marketing formatting: Reduced char penalty ({base_char_score:.1f} → {adjusted_score:.1f})")
            elif invisible_count < 500:
                
                adjusted_score = base_char_score * 0.5
                correlations.append(f"⚠️ Moderate char obfuscation in legitimate service ({invisible_count} chars)")
            else:
                
                adjusted_score = base_char_score * 0.8
                critical_indicators.append(f"Excessive character obfuscation even for marketing email ({invisible_count} chars)")
            char_score += adjusted_score
        else:
            
            char_score += base_char_score
            if invisible_count > 50:
                critical_indicators.append(f"Excessive character obfuscation ({invisible_count} invisible chars)")
    
    if homograph_count > 0:
        char_score += min(homograph_count * 0.8, 8)
        if homograph_count > 5:
            critical_indicators.append(f"Homograph attack detected ({homograph_count} lookalike chars)")
    
    if has_script_mixing:
        char_score += 7
        if has_cyrillic:
            char_score += 5
    
    
    if invisible_count > 20 and keyword_score > 0:
        if not is_legitimate_service:
            correlation_bonus = 12
            char_score += correlation_bonus
            correlations.append(f"🔥 CRITICAL: Heavy character evasion + phishing keywords (+{correlation_bonus})")
        else:
            
            correlation_bonus = 6
            char_score += correlation_bonus
            correlations.append(f"⚠️ Marketing tracking + phishing keywords (+{correlation_bonus})")
    
    if has_cyrillic and keyword_score > 0 and not is_legitimate_service:
        correlation_bonus = 10
        char_score += correlation_bonus
        correlations.append(f"⚠️ HIGH RISK: Cyrillic characters + phishing keywords (+{correlation_bonus})")
    
    if char_score > 0:
        char_score = min(char_score, 30)
        score += char_score
        score_breakdown.append(f"🔤 Character/Encoding Issues: +{char_score:.1f} points")
    
    
    url_score = 0
    
    if ip_urls > 0:
        url_score += min(ip_urls * 10, 15)
        if ip_urls > 2:
            critical_indicators.append(f"Multiple IP-based URLs detected ({ip_urls})")
    
    if suspicious_file_urls > 0:
        url_score += min(suspicious_file_urls * 15, 20)
        critical_indicators.append(f"Suspicious file downloads detected ({suspicious_file_urls})")
    
    if highly_obfuscated > 0:
        base_obfuscation_score = min(highly_obfuscated * 8, 15)
        if is_legitimate_service:
            
            adjusted_score = base_obfuscation_score * 0.5
            correlations.append(f"📧 Marketing URL tracking: Reduced obfuscation penalty ({base_obfuscation_score} → {adjusted_score:.1f})")
            url_score += adjusted_score
        else:
            url_score += base_obfuscation_score
            critical_indicators.append(f"Heavily obfuscated URLs ({highly_obfuscated})")
    
    if obfuscated_urls > 0:
        base_obfuscation_score = min(obfuscated_urls * 3, 10)
        if is_legitimate_service:
            
            url_score += base_obfuscation_score * 0.3
        else:
            url_score += base_obfuscation_score
    
    
    if obfuscated_urls > 0 and keyword_score > 0 and (invisible_count > 0 or has_cyrillic):
        if not is_legitimate_service:
            correlation_bonus = 15
            url_score += correlation_bonus
            correlations.append(f"🔥 CRITICAL: URL obfuscation + keywords + character evasion (+{correlation_bonus})")
        else:
            
            correlation_bonus = 8
            url_score += correlation_bonus
            correlations.append(f"📧 Marketing email with concerning elements (+{correlation_bonus})")
    
    if obfuscated_urls > 5 and invisible_count > 20:
        if not is_legitimate_service:
            correlation_bonus = 10
            url_score += correlation_bonus
            correlations.append(f"🚨 ADVANCED EVASION: Multiple obfuscated URLs + heavy character masking")
    
    if url_score > 0:
        url_score = min(url_score, 35)
        score += url_score
        score_breakdown.append(f"🔗 Suspicious URLs: +{url_score:.1f} points")
    
    
    other_score = 0
    
    if result.get('external_ips'):
        other_score += min(len(result['external_ips']) * 2, 4)
    
    if result.get('is_phishing_sim'):
        other_score += 6
        critical_indicators.append("Potential phishing simulation/training detected")
    
    if other_score > 0:
        score += other_score
        score_breakdown.append(f"🔍 Other Issues: +{other_score} points")
    
    
    
    threat_vectors = 0
    if keyword_score > 0: threat_vectors += 1
    if invisible_count > 10: threat_vectors += 1
    if obfuscated_urls > 0: threat_vectors += 1
    if has_cyrillic: threat_vectors += 1
    if auth_failures: threat_vectors += 1
    
    
    if threat_vectors >= 4:
        if not is_legitimate_service:
            correlation_bonus = 15
            score += correlation_bonus
            correlations.append(f"🚨 MULTI-VECTOR ATTACK: {threat_vectors} threat types detected (+{correlation_bonus})")
        else:
            correlation_bonus = 8
            score += correlation_bonus
            correlations.append(f"📧 Marketing email with multiple indicators (+{correlation_bonus})")
    elif threat_vectors >= 3:
        correlation_bonus = 8 if not is_legitimate_service else 4
        score += correlation_bonus
        correlations.append(f"⚠️ COORDINATED THREATS: {threat_vectors} attack vectors detected (+{correlation_bonus})")
    
    
    
    if is_legitimate_service and legitimacy_score > 70:
        
        original_score = score
        score = score * 0.75  
        correlations.append(f"📧 High-confidence legitimate service: Final score adjustment ({original_score:.1f} → {score:.1f})")
    
    
    final_score = min(score, 100)
    
    
    formatted_factors = []
    formatted_factors.append("=== 📊 RISK SCORE BREAKDOWN ===")
    formatted_factors.extend(score_breakdown)
    formatted_factors.append(f"**FINAL TOTAL: {final_score}/100**")
    
    
    if business_context:
        formatted_factors.append("\n=== 📧 BUSINESS CONTEXT ===")
        if business_context.get('is_likely_legitimate'):
            service_name = business_context.get('marketing_service', 'Unknown Service')
            formatted_factors.append(f"• Legitimate Marketing Service: {service_name}")
            formatted_factors.append(f"• Legitimacy Score: {legitimacy_score}/100")
        
        if business_context.get('business_indicators'):
            indicators = business_context['business_indicators'] 
            formatted_factors.append(f"• Business Indicators: {len(indicators)} found")
    
    if critical_indicators:
        formatted_factors.append("\n=== 🚨 CRITICAL INDICATORS ===")
        formatted_factors.extend([f"• {indicator}" for indicator in critical_indicators])
    
    if correlations:
        formatted_factors.append("\n=== 🔗 CORRELATION ANALYSIS ===")
        formatted_factors.extend([f"• {correlation}" for correlation in correlations])
    
    return int(final_score), formatted_factors