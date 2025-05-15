"""
Email parsing for MSG and EML files
"""

import re
import email
import email.policy
import chardet
import extract_msg
from extract_msg.exceptions import InvalidFileFormatError
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from detectors.url_detector import decode_safelinks
from utils.display import print_info


class EmailParser:
    """Base class for email parsing."""
    
    def extract_body_and_urls_from_eml(self, msg):
        """Extract body content and URLs from an email message object."""
        body = ""
        urls = []
        domains = set()
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                    
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            # Try to detect encoding
                            detected = chardet.detect(payload)
                            encoding = detected.get('encoding', 'utf-8')
                            payload_text = payload.decode(encoding, errors='ignore')
                            body += payload_text + "\n"
                            
                            # Extract URLs from this part
                            part_urls = re.findall(r'https?://\S+', payload_text)
                            urls.extend(part_urls)
                            
                            # Extract domains from URLs
                            for url in part_urls:
                                domain = self.extract_domain(url)
                                if domain:
                                    domains.add(domain)
                    except Exception as e:
                        body += f"[Error decoding message part: {str(e)}]\n"
                elif content_type == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            # Try to detect encoding
                            detected = chardet.detect(payload)
                            encoding = detected.get('encoding', 'utf-8')
                            payload_text = payload.decode(encoding, errors='ignore')
                            
                            # Extract URLs from HTML
                            html_urls = re.findall(r'https?://\S+', payload_text)
                            urls.extend(html_urls)
                            
                            # Also check href attributes
                            soup = BeautifulSoup(payload_text, 'html.parser')
                            for link in soup.find_all('a', href=True):
                                if link['href'].startswith(('http://', 'https://')):
                                    urls.append(link['href'])
                            
                            # Convert HTML to text for body
                            body += soup.get_text(separator='\n', strip=True) + "\n"
                            
                            # Extract domains from URLs
                            for url in html_urls:
                                domain = self.extract_domain(url)
                                if domain:
                                    domains.add(domain)
                    except Exception as e:
                        body += f"[Error decoding HTML part: {str(e)}]\n"
        else:
            # Not multipart - get the payload directly
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    # Try to detect encoding
                    detected = chardet.detect(payload)
                    encoding = detected.get('encoding', 'utf-8')
                    body = payload.decode(encoding, errors='ignore')
                    
                    # Extract URLs
                    urls = re.findall(r'https?://\S+', body)
                    
                    # Extract domains from URLs
                    for url in urls:
                        domain = self.extract_domain(url)
                        if domain:
                            domains.add(domain)
            except Exception as e:
                body = f"[Error decoding message body: {str(e)}]"
        
        # Decode SafeLinks URLs
        urls = [decode_safelinks(url.rstrip('>')) for url in urls]
        
        return body, list(set(urls)), list(domains)
    
    def extract_domain(self, url):
        """Extract domain from URL."""
        try:
            return urlparse(url).netloc
        except:
            return None


class MsgParser(EmailParser):
    """Parser for MSG files."""
    
    def parse(self, file_path):
        """Parse a .msg file and extract relevant information."""
        try:
            msg = extract_msg.Message(file_path)
            
            subject = msg.subject or "No Subject"
            sender = msg.sender or "Unknown Sender"
            to = msg.to or "Unknown Recipient"
            cc = msg.cc or ""
            
            headers = dict(msg.header) if hasattr(msg, 'header') else {}
            
            body = msg.body or ""
            
            # Extract plain text from HTML if body is HTML
            if body.strip().startswith('<'):
                soup = BeautifulSoup(body, 'html.parser')
                body = soup.get_text(separator='\n', strip=True)
            
            urls = re.findall(r'https?://\S+', body)
            if not urls:
                # Also check HTML body if available
                if hasattr(msg, 'htmlBody') and msg.htmlBody:
                    urls.extend(re.findall(r'https?://\S+', msg.htmlBody))
            
            urls = [decode_safelinks(url.rstrip('>')) for url in urls]
            domains = list(set([urlparse(url).netloc for url in urls if url]))
            
            return {
                'subject': subject,
                'from': sender,
                'to': to,
                'cc': cc,
                'date': None,  # MSG files don't easily provide date
                'headers': headers,
                'urls': urls,
                'domains': domains,
                'body': body,
                'detected_encoding': None
            }
            
        except InvalidFileFormatError:
            # If it's not a proper .msg file, it might be an .eml file
            print_info("File doesn't appear to be a proper .msg file. Attempting to process as .eml file...")
            return EmlParser().parse(file_path)


class EmlParser(EmailParser):
    """Parser for EML files."""
    
    def parse(self, file_path):
        """Parse an .eml file and extract relevant information."""
        # Try to detect encoding first
        with open(file_path, 'rb') as file:
            raw_data = file.read()
            detected_encoding = chardet.detect(raw_data)
            encoding = detected_encoding.get('encoding', 'utf-8')
        
        # Read with detected encoding
        with open(file_path, 'r', encoding=encoding, errors='ignore') as file:
            raw_email = file.read()
        
        # Parse the email
        msg = email.message_from_string(raw_email, policy=email.policy.default)
        
        # Extract headers
        headers = {}
        for header, value in msg.items():
            headers[header] = value
        
        # Extract basic email information
        subject = msg.get('Subject', 'No Subject')
        from_addr = msg.get('From', 'Unknown Sender')
        to_addr = msg.get('To', 'Unknown Recipient')
        cc_addr = msg.get('Cc', '')
        date = msg.get('Date', 'Unknown Date')
        
        # Extract body and URLs
        body, urls, domains = self.extract_body_and_urls_from_eml(msg)
        
        return {
            'subject': subject,
            'from': from_addr,
            'to': to_addr,
            'cc': cc_addr,
            'date': date,
            'headers': headers,
            'urls': urls,
            'domains': domains,
            'body': body,
            'detected_encoding': detected_encoding
        }


def create_parser(file_path):
    """Factory function to create the appropriate parser based on file extension."""
    if file_path.lower().endswith('.msg'):
        return MsgParser()
    elif file_path.lower().endswith('.eml'):
        return EmlParser()
    else:
        raise ValueError(f"Unsupported file type: {file_path}")