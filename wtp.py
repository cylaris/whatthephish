
"""
What's The Phish - Email Phishing Analysis Tool
Main entry point for the application
"""

import argparse
import sys
import os
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))

from core.analyzers import EmailAnalyzer
from core.confidence import calculate_risk_confidence, ConfidenceLevel
from utils.colors import Colors
from utils.display import (
    print_banner, print_section, print_subsection, print_key_value,
    print_warning, print_error, print_info, print_success,
    format_body_for_display, format_header_for_display
)
from core.keyword_analyzer import KeywordAnalyzer


os.environ['FORCE_COLOR'] = '1'

HEADER = r"""
 __    __ _           _  _____ _            ___ _     _     _     
/ / /\ \ \ |__   __ _| |/__   \ |__   ___  / _ \ |__ (_)___| |__  
\ \/  \/ / '_ \ / _ | __|/ /\/ '_ \ / _ \/ /_)/ '_ \| / __| '_ \ 
 \  /\  /| | | | (_| | |_/ /  | | | |  __/ ___/| | | | \__ \ | | |
  \/  \/ |_| |_|\__,_|\__\/   |_| |_|\___\/    |_| |_|___/_| |_| v2.1
                Lightweight CLI email analysis tool
<-------------------------------------------------------------------->
GitHub: https://github.com/cylaris/whatthephish
Made with ❤️ by ntwrite
❗Usage: python3 wtp.py -msg <path_to_msg_file> [options]
❗Use -h for help with options
"""


def setup_argparse():
    """Setup command line argument parsing."""
    parser = argparse.ArgumentParser(description="What's The Phish - A rapid email phishing analysis tool.")
    parser.add_argument('-msg', '--message', required=True, help='Path to the .msg or .eml file to analyse')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--no-truncate', action='store_true', help='Disable truncation of email body and headers')
    parser.add_argument('--create-keywords', action='store_true', help='Create default keyword files and exit')
    return parser.parse_args()


def display_results(result, args):
    """Display the analysis results with proper formatting."""
    
    risk_score = result['risk_score']
    business_context = result.get('business_context', {})
    
    
    if risk_score >= 80:
        risk_level = "CRITICAL"
        risk_color = Colors.RED
        threat_emoji = "🚨"
    elif risk_score >= 60:
        risk_level = "HIGH RISK"
        risk_color = Colors.RED
        threat_emoji = "⚠️"
    elif risk_score >= 40:
        risk_level = "MEDIUM RISK"
        risk_color = Colors.YELLOW
        threat_emoji = "⚠️"
    else:
        risk_level = "LOW RISK"
        risk_color = Colors.GREEN
        threat_emoji = "✅"
    
    print_banner(f"{threat_emoji} {risk_level} - Score: {risk_score}/100", risk_color)
    
    
    if business_context and business_context.get('is_likely_legitimate'):
        print_section("📧 Business Context Analysis", Colors.BLUE)
        marketing_service = business_context.get('marketing_service')
        if marketing_service:
            print_key_value("Legitimate Service Detected", marketing_service)
        
        legitimacy_score = business_context.get('legitimacy_score', 0)
        print_key_value("Business Legitimacy Score", f"{legitimacy_score}/100")
        
        factors = business_context.get('factors', [])
        if factors:
            print_subsection("Legitimacy Factors:")
            for factor in factors:
                print(f"  • {factor}")
    
    
    if result['risk_factors']:
        print_section("🔍 Risk Assessment Details", Colors.CYAN)
        current_section = None
        
        for factor in result['risk_factors']:
            
            if factor.startswith("==="):
                section_name = factor.strip("= ")
                if section_name != current_section:
                    current_section = section_name
                    
                    if "SCORE BREAKDOWN" in section_name:
                        print_subsection(f"📊 Score Breakdown", Colors.BLUE)
                    elif "BUSINESS CONTEXT" in section_name:
                        print_subsection(f"📧 Business Context", Colors.BLUE)
                    elif "CRITICAL INDICATORS" in section_name:
                        print_subsection(f"🚨 Critical Indicators", Colors.RED)
                    elif "CORRELATION ANALYSIS" in section_name:
                        print_subsection(f"🔗 Threat Correlations", Colors.MAGENTA)
                continue
            
            
            if factor.startswith("**FINAL TOTAL"):
                print(f"\n{Colors.BOLD}{Colors.CYAN}{factor}{Colors.ENDC}\n")
                continue
            
            
            if factor.startswith("•"):
                
                if "CRITICAL" in factor or "🔥" in factor:
                    print(f"  {Colors.RED}{factor}{Colors.ENDC}")
                elif "HIGH RISK" in factor or "🚨" in factor:
                    print(f"  {Colors.YELLOW}{factor}{Colors.ENDC}")
                elif "CORRELATION" in factor or "MULTI-VECTOR" in factor:
                    print(f"  {Colors.MAGENTA}{factor}{Colors.ENDC}")
                elif "📧" in factor:  
                    print(f"  {Colors.BLUE}{factor}{Colors.ENDC}")
                else:
                    print(f"  {factor}")
            else:
                
                print(f"  {factor}")
    
    
    confidence_result = calculate_risk_confidence(result, business_context)
    confidence_level = confidence_result.get('confidence_level')
    
    if confidence_result:
        print_section("🎯 Confidence Analysis", Colors.CYAN)
        overall_conf = confidence_result.get('confidence_score', 0)
        print_key_value("Overall Confidence", f"{overall_conf*100:.1f}% ({confidence_level.label if confidence_level else 'Unknown'})")
        
        component_confidences = confidence_result.get('component_confidences', {})
        if component_confidences and args.verbose:
            print_subsection("Component Confidences:")
            for component, conf in component_confidences.items():
                color = Colors.GREEN if conf > 0.7 else Colors.YELLOW if conf > 0.4 else Colors.RED
                print(f"  • {component.title()}: {color}{conf*100:.1f}%{Colors.ENDC}")
    
    
    content_analysis, keyword_results = result['content_analysis']
    print_section("Keyword Analysis", Colors.MAGENTA)
    
    if keyword_results and keyword_results.get('total_score', 0) > 0:
        print_key_value("Total Keyword Score", keyword_results['total_score'])
        
        if keyword_results.get('categories'):
            print_subsection("Matches Found:")
            for category, data in keyword_results['categories'].items():
                print_key_value(
                    data['description'], 
                    f"{data['count']} unique keywords ({data['total_occurrences']} total occurrences)"
                )
                
                
                if args.verbose and category in keyword_results.get('found_keywords', {}):
                    keyword_details = keyword_results['found_keywords'][category]
                    print("    Keywords found:")
                    for kw_data in keyword_details[:5]:  
                        context_parts = []
                        if kw_data['subject_count'] > 0:
                            context_parts.append(f"subject:{kw_data['subject_count']}")
                        if kw_data['body_count'] > 0:
                            context_parts.append(f"body:{kw_data['body_count']}")
                        context = f" ({', '.join(context_parts)})" if context_parts else ""
                        print(f"      • '{kw_data['keyword']}'{context}")
                    
                    if len(keyword_details) > 5:
                        print(f"      ... and {len(keyword_details) - 5} more")
    else:
        print("No suspicious keywords detected")
    
    
    if result.get('encoding_issues') or result.get('spacing_issues') or result.get('suspicious_chars'):
        print_section("Character Encoding Analysis", Colors.MAGENTA)
        
        if result.get('detected_encoding'):
            print_key_value("Detected Encoding", f"{result['detected_encoding']['encoding']} (confidence: {result['detected_encoding']['confidence']:.2%})")
        
        
        if result.get('encoding_issues'):
            print_subsection("Character Analysis Summary:")
            
            
            invisible_counts = {}
            for issue in result['encoding_issues']:
                if issue.startswith('-') and ':' in issue:
                    char_type = issue.split(':')[0].strip('- ')
                    count = int(issue.split(':')[1].strip())
                    invisible_counts[char_type] = count
            
            
            main_issues = [issue for issue in result['encoding_issues'] if not issue.startswith('-')]
            for issue in main_issues:
                if "invisible" in issue.lower():
                    print_warning(f"{issue}")
                    
                    if invisible_counts:
                        for char_type, count in sorted(invisible_counts.items()):
                            print(f"    • {char_type}: {count}")
                else:
                    print_warning(issue)
        
        if result.get('spacing_issues'):
            print_subsection("Spacing/Evasion Patterns:")
            for issue in result['spacing_issues']:
                print_warning(issue)
        
        
        if result.get('suspicious_chars'):
            print_subsection("Character Threat Assessment:")
            
            
            char_analysis = {}
            for char, code_point, char_name, range_name, position in result['suspicious_chars']:
                category = range_name
                if category == "Invisible Character":
                    category = f"🔴 {category}"
                elif category == "Potential Homograph":
                    category = f"🟡 {category}"
                else:
                    category = f"🔵 {category}"
                
                if category not in char_analysis:
                    char_analysis[category] = []
                char_analysis[category].append((char_name, code_point))
            
            
            for category in sorted(char_analysis.keys()):
                chars = char_analysis[category]
                unique_chars = {}
                for char_name, code_point in chars:
                    unique_chars[char_name] = unique_chars.get(char_name, 0) + 1
                
                total_count = sum(unique_chars.values())
                print(f"  • {category}: {total_count} characters ({len(unique_chars)} unique types)")
                
                if args.verbose:
                    
                    sorted_chars = sorted(unique_chars.items(), key=lambda x: x[1], reverse=True)
                    for char_name, count in sorted_chars[:3]:
                        print(f"    - {char_name}: {count}")
                    if len(sorted_chars) > 3:
                        print(f"    - ... and {len(sorted_chars) - 3} more types")
    
    
    print_section("Email Details")
    print_key_value("Subject", result['flagged_subject'] if result.get('flagged_subject') != result['subject'] else result['subject'])
    print_key_value("From", result['from'])
    print_key_value("To", result['to'])
    if result['cc']:
        print_key_value("CC", result['cc'])
    if 'date' in result:
        print_key_value("Date", result['date'])
    
    
    print_section("Authentication Results")
    auth_results = result['auth_results']
    if auth_results:
        for auth_type, status in auth_results.items():
            color = Colors.GREEN if status == 'PASS' else Colors.RED
            print_key_value(auth_type, f"{color}{status}{Colors.ENDC}")
    else:
        print_warning("No authentication results found")
    
    
    print_section("Network Information")
    if result['external_ips']:
        print_subsection("External IP Addresses:")
        for ip in result['external_ips']:
            print(f"  • {ip}")
    else:
        print("No external IP addresses identified")
    
    
    print_section("URL Analysis")
    if result['urls']:
        total_urls = len(result['urls'])
        display_limit = 10 if not args.verbose else total_urls
        
        print_subsection("URLs Found:")
        for i, url in enumerate(result['urls'][:display_limit]):
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
            if analysis.get('obfuscation_score', 0) > 5:
                indicators.append(f"{Colors.MAGENTA}HEAVILY OBFUSCATED{Colors.ENDC}")
            elif analysis.get('obfuscation_score', 0) > 2:
                indicators.append(f"{Colors.MAGENTA}OBFUSCATED{Colors.ENDC}")
            if analysis.get('file_extensions'):
                indicators.append(f"{Colors.CYAN}FILE: {', '.join(analysis['file_extensions'])}{Colors.ENDC}")
            
            indicator_str = f" [{', '.join(indicators)}]" if indicators else ""
            
            
            final_url = analysis.get('final_decoded_url', url)
            url_display = url
            
            
            if len(url_display) > 100:
                url_display = url_display[:80] + "..."
            
            print(f"  {i+1}. {url_display}{indicator_str}")
            
            
            if final_url != url and len(final_url) > len(url) + 10:
                decoded_display = final_url
                if len(decoded_display) > 100:
                    decoded_display = decoded_display[:80] + "..."
                print(f"      🔓 Decoded: {decoded_display}")
            
            
            if args.verbose and analysis.get('obfuscation_score', 0) > 0:
                print(f"      Obfuscation Score: {analysis['obfuscation_score']}")
                if analysis.get('suspicious_patterns'):
                    print(f"      Patterns: {', '.join(analysis['suspicious_patterns'][:3])}")
                if analysis.get('encoding_layers', 0) > 0:
                    print(f"      Encoding Layers: {analysis['encoding_layers']}")
        
        
        if total_urls > display_limit:
            remaining = total_urls - display_limit
            print(f"\n  ... and {remaining} more URLs")
            print(f"  {Colors.CYAN}💡 Use --verbose (-v) to see all {total_urls} URLs{Colors.ENDC}")
        
        
        print_subsection("URL Analysis Summary:")
        obfuscated_count = sum(1 for analysis in result['url_analysis'].values() if analysis.get('obfuscation_score', 0) > 2)
        highly_obfuscated_count = sum(1 for analysis in result['url_analysis'].values() if analysis.get('obfuscation_score', 0) > 5)
        ip_count = sum(1 for analysis in result['url_analysis'].values() if analysis.get('is_ip'))
        
        if obfuscated_count > 0:
            print(f"  • {Colors.MAGENTA}Obfuscated URLs: {obfuscated_count}{Colors.ENDC}")
        if highly_obfuscated_count > 0:
            print(f"  • {Colors.RED}Heavily Obfuscated: {highly_obfuscated_count}{Colors.ENDC}")
        if ip_count > 0:
            print(f"  • {Colors.RED}IP-based URLs: {ip_count}{Colors.ENDC}")
        
        print_subsection("Unique Domains:")
        for domain in result['domains'][:10]:
            print(f"  • {domain}")
        if len(result['domains']) > 10:
            print(f"  ... and {len(result['domains']) - 10} more domains")
    else:
        print("No URLs found")
    
    
    if result['is_phishing_sim']:
        print_section("Phishing Simulation Detection", Colors.YELLOW)
        print_warning("This email contains Microsoft anti-spam headers but lacks typical email routing headers.")
        print_warning("It may be part of a phishing awareness exercise.")
    
    
    if args.verbose:
        print_section("Email Headers")
        important_headers = ['Received', 'Authentication-Results', 'X-Microsoft-Antispam', 'X-MS-Exchange-Organization', 'Return-Path']
        for header, value in sorted(result['headers'].items()):
            if any(h.lower() in header.lower() for h in important_headers):
                print_key_value(header, format_header_for_display(value, no_truncate=args.no_truncate), Colors.YELLOW)
    
    
    print_section("Email Body (keywords and suspicious chars highlighted)")
    
    
    display_body = result.get('flagged_body', result['body'])
    if keyword_results and keyword_results.get('highlighted_body'):
        display_body = keyword_results['highlighted_body']
        
        if result.get('suspicious_chars'):
            from detectors.character_detector import detect_and_flag_suspicious_chars
            flagged_highlighted_body, _, _ = detect_and_flag_suspicious_chars(display_body)
            display_body = flagged_highlighted_body
    
    print(format_body_for_display(display_body, no_truncate=args.no_truncate))
    
    print_banner("Analysis Complete", Colors.BLUE)
    
    
    print_section("📋 Analysis Summary", Colors.CYAN)
    
    
    print(f"{Colors.BOLD}Email Statistics:{Colors.ENDC}")
    print(f"  • Total URLs: {len(result['urls'])}")
    print(f"  • Unique Domains: {len(result['domains'])}")
    print(f"  • External IPs: {len(result['external_ips'])}")
    
    print(f"\n{Colors.BOLD}Threat Indicators:{Colors.ENDC}")
    print(f"  • Suspicious Characters: {len(result.get('suspicious_chars', []))}")
    print(f"  • Keyword Score: {keyword_results.get('total_score', 0)}")
    
    
    if result.get('url_analysis'):
        obfuscated_urls = sum(1 for analysis in result['url_analysis'].values() if analysis.get('obfuscation_score', 0) > 2)
        if obfuscated_urls > 0:
            print(f"  • Obfuscated URLs: {obfuscated_urls}")
    
    
    print(f"\n{Colors.BOLD}Final Risk Assessment:{Colors.ENDC}")
    if risk_score >= 80:
        print(f"  🚨 {Colors.RED}{Colors.BOLD}CRITICAL THREAT DETECTED{Colors.ENDC}")
        print(f"     Immediate action recommended")
    elif risk_score >= 60:
        print(f"  ⚠️  {Colors.RED}{Colors.BOLD}HIGH RISK{Colors.ENDC} - Score: {risk_score}/100")
        print(f"     Multiple threat indicators present")
    elif risk_score >= 40:
        print(f"  ⚠️  {Colors.YELLOW}{Colors.BOLD}MEDIUM RISK{Colors.ENDC} - Score: {risk_score}/100")
        print(f"     Some suspicious elements detected")
    else:
        print(f"  ✅ {Colors.GREEN}{Colors.BOLD}LOW RISK{Colors.ENDC} - Score: {risk_score}/100")
        print(f"     No significant threats detected")
    
    
    if risk_score > 60:
        
        correlations = []
        in_correlation_section = False
        
        for factor in result['risk_factors']:
            if "=== 🔗 CORRELATION ANALYSIS ===" in factor:
                in_correlation_section = True
                continue
            elif factor.startswith("==="):
                in_correlation_section = False
                continue
            elif in_correlation_section and factor.startswith("•"):
                correlations.append(factor)
        
        if correlations:
            print(f"\n{Colors.BOLD}Key Threat Correlations:{Colors.ENDC}")
            for correlation in correlations[:2]:  
                clean_correlation = correlation.replace("• ", "").replace("🔥", "").replace("🚨", "").strip()
                print(f"  • {clean_correlation}")
    
    
    print(f"\n{Colors.BOLD}Analysis Options:{Colors.ENDC}")
    if not args.no_truncate:
        print(f"  💡 Use --no-truncate to see full content without truncation")
    if not args.verbose:
        print(f"  💡 Use --verbose (-v) to see all URLs and detailed analysis")
    print(f"  💡 Use --create-keywords to generate custom keyword files")


def main():
    """Main entry point for the application."""
    print(HEADER)
    args = setup_argparse()
    
    
    if args.create_keywords:
        analyzer = KeywordAnalyzer()
        analyzer.create_default_keyword_files()
        print_success("Default keyword files created successfully!")
        sys.exit(0)
    
    file_path = args.message
    
    if not os.path.exists(file_path):
        print_error(f"File not found: {file_path}")
        sys.exit(1)
    
    
    _, ext = os.path.splitext(file_path.lower())
    if ext not in ['.msg', '.eml']:
        print_error(f"Unsupported file type: {ext}. Please provide a .msg or .eml file.")
        sys.exit(1)
    
    file_type = ext[1:]  
    print_info(f"Analysing {file_type.upper()} file: {os.path.basename(file_path)}")
    
    
    try:
        analyzer = EmailAnalyzer()
        result = analyzer.analyze_file(file_path)
    except Exception as e:
        print_error(f"Error processing file: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    
    print_banner("Email Analysis Report", Colors.BLUE)
    display_results(result, args)


if __name__ == "__main__":
    main()