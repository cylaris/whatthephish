"""
Display and formatting utilities for WTP
"""

from .colors import Colors


def print_banner(text, color=Colors.BLUE):
    """Print a banner with the given text and color."""
    banner_width = 80
    print(f"\n{color}{Colors.BOLD}{'=' * banner_width}")
    print(f"{text:^{banner_width}}")
    print(f"{'=' * banner_width}{Colors.ENDC}")


def print_section(title, color=Colors.GREEN):
    """Print a section header."""
    print(f"\n{color}{Colors.BOLD}{title}")
    print(f"{'-' * len(title)}{Colors.ENDC}")


def print_subsection(title, color=Colors.CYAN):
    """Print a subsection header."""
    print(f"\n{color}{Colors.BOLD}  {title}{Colors.ENDC}")


def print_key_value(key, value, color=Colors.BLUE, indent=0):
    """Print a key-value pair with proper formatting."""
    spaces = " " * indent
    if isinstance(value, str) and '\n' in value:
        # Multi-line value - format properly
        lines = value.split('\n')
        print(f"{spaces}{color}{key}:{Colors.ENDC}")
        for line in lines:
            print(f"{spaces}  {line}")
    else:
        print(f"{spaces}{color}{key}:{Colors.ENDC} {value}")


def print_warning(text):
    """Print a warning message."""
    print(f"{Colors.YELLOW}{Colors.BOLD}⚠️  {text}{Colors.ENDC}")


def print_error(text):
    """Print an error message."""
    print(f"{Colors.RED}{Colors.BOLD}❌ {text}{Colors.ENDC}")


def print_info(text):
    """Print an info message."""
    print(f"{Colors.BLUE}{Colors.BOLD}ℹ️  {text}{Colors.ENDC}")


def print_success(text):
    """Print a success message."""
    print(f"{Colors.GREEN}{Colors.BOLD}✅ {text}{Colors.ENDC}")


def format_body_for_display(body, max_lines=20, no_truncate=False):
    """Format body for display, truncating if necessary."""
    if not body:
        return "No body content found"
    
    if no_truncate:
        return body
    
    lines = body.split('\n')
    if len(lines) > max_lines:
        truncated = '\n'.join(lines[:max_lines])
        truncated += f"\n\n{Colors.YELLOW}[Body truncated - {len(lines) - max_lines} more lines...]{Colors.ENDC}"
        return truncated
    return body


def format_header_for_display(value, max_length=100, no_truncate=False):
    """Format header value for display, truncating if necessary."""
    if not value:
        return ""
    
    if no_truncate:
        return value
        
    if len(value) > max_length:
        return value[:max_length] + "..."
    return value