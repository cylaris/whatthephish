"""
Character encoding and obfuscation detection
"""

import re
import unicodedata
from utils.colors import Colors


def detect_and_flag_suspicious_chars(text):
    """Detect suspicious characters and mixed scripts that could be evasion attempts."""
    if not text:
        return text, [], []
    
    issues = []
    flagged_text = text
    suspicious_chars = []
    
    # Check for invisible/zero-width characters
    invisible_chars = {
        '\u200B': 'ZERO WIDTH SPACE',
        '\u200C': 'ZERO WIDTH NON-JOINER', 
        '\u200D': 'ZERO WIDTH JOINER',
        '\u2060': 'WORD JOINER',
        '\u3000': 'IDEOGRAPHIC SPACE',
        '\uFEFF': 'ZERO WIDTH NO-BREAK SPACE',
        '\u200E': 'LEFT-TO-RIGHT MARK',
        '\u200F': 'RIGHT-TO-LEFT MARK'
    }
    
    # Count each type of invisible character
    invisible_counts = {}
    char_positions = []
    
    for i, char in enumerate(text):
        code_point = ord(char)
        
        # Check for invisible characters (prioritize these)
        if char in invisible_chars:
            char_name = invisible_chars[char]
            invisible_counts[char_name] = invisible_counts.get(char_name, 0) + 1
            suspicious_chars.append((char, code_point, char_name, "Invisible Character", i))
            char_positions.append(i)
        # Check for other suspicious characters in specific ranges
        elif 0x0100 <= code_point <= 0x017F:  # Latin Extended-A (common for lookalikes)
            char_name = unicodedata.name(char, f"UNKNOWN-{code_point}")
            suspicious_chars.append((char, code_point, char_name, "Latin Extended", i))
            char_positions.append(i)
        elif 0xFF00 <= code_point <= 0xFFEF:  # Fullwidth/Halfwidth Forms
            char_name = unicodedata.name(char, f"UNKNOWN-{code_point}")
            suspicious_chars.append((char, code_point, char_name, "Fullwidth Form", i))
            char_positions.append(i)
        # Check for homograph attacks (lookalike non-ASCII letters)
        elif code_point > 127 and char.isalpha():
            # Only flag if it's a potential lookalike
            normalized = unicodedata.normalize('NFD', char)[0]
            if normalized in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ':
                char_name = unicodedata.name(char, f"UNKNOWN-{code_point}")
                suspicious_chars.append((char, code_point, char_name, "Potential Homograph", i))
                char_positions.append(i)
    
    # Create flagged version of text with suspicious chars highlighted
    if char_positions:
        flagged_text = ""
        last_pos = 0
        for pos in char_positions:
            flagged_text += text[last_pos:pos]
            flagged_text += f"{Colors.RED}{Colors.BOLD}[{text[pos]}]{Colors.ENDC}"
            last_pos = pos + 1
        flagged_text += text[last_pos:]
    
    # Generate issue summaries
    if invisible_counts:
        total_invisible = sum(invisible_counts.values())
        issues.append(f"Found {total_invisible} invisible/formatting characters")
        
        # Detail each type
        for char_type, count in sorted(invisible_counts.items()):
            if count > 0:
                issues.append(f"- {char_type}: {count}")
    
    # Check for script mixing (potential homograph attack)
    scripts = set()
    for char in text:
        if char.isalpha():
            try:
                script = unicodedata.name(char).split()[0]
                scripts.add(script)
            except:
                pass
    
    if len(scripts) > 1:
        issues.append(f"Multiple scripts detected: {', '.join(sorted(scripts))}")
    
    return flagged_text, suspicious_chars, issues


def detect_character_spacing_evasion(text):
    """Detect character spacing evasion techniques."""
    if not text:
        return []
    
    issues = []
    
    # Look for suspicious spacing patterns
    # Pattern like: d o c u m e n t
    spaced_pattern = re.compile(r'\b[a-zA-Z](\s+[a-zA-Z]){3,}\b')
    spaced_matches = spaced_pattern.findall(text)
    if spaced_matches:
        issues.append(f"Suspicious character spacing detected (potential evasion)")
    
    # Look for mixed spacing with non-breaking spaces
    if '\u00A0' in text:  # Non-breaking space
        issues.append("Non-breaking spaces detected")
    
    # Look for invisible character insertions
    invisibles_count = sum(1 for char in text if unicodedata.category(char) == 'Cf')
    if invisibles_count > 0:
        issues.append(f"Found {invisibles_count} formatting/invisible characters")
    
    return issues