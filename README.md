![image](https://github.com/user-attachments/assets/a33816ce-d8eb-4c55-b4ac-7040b2f88337)
## WhatThePhish v2.1
A significantly enhanced email phishing analysis tool with advanced character analysis, business context detection, and comprehensive risk assessment capabilities.

![Version](https://img.shields.io/badge/Version-2.1-brightgreen)
![Language](https://img.shields.io/badge/Language-Python-blue)
![License](https://img.shields.io/badge/License-GPL3.0-green)
## Installation
- Create a folder for this project, then run:
```bash
git clone https://github.com/cylaris/whatthephish.git
```
- Move into that dir
```
cd whatthephish
```
- Then install the requirements:
```
pip install -r requirements.txt
```
## Current Features
### Advanced Character Analysis Engine
- **Suspicious Character Detection**: Comprehensive detection of potential evasion techniques:
  - Homograph attacks (lookalike characters)
  - Invisible/zero-width characters with detailed breakdown by type
  - Mixed script detection (Latin, Cyrillic, etc.)
  - Suspicious Unicode ranges
- **Character Spacing Evasion**: Detection of artificial spacing and formatting tricks
- **Visual Flagging**: Characters highlighted in red when suspicious patterns detected
- **Character Threat Assessment**: Categorised view of character threats with emoji indicators
![image](https://github.com/user-attachments/assets/2305fbeb-feaf-4fb6-ac48-ce1c44a1e9fa)

<sub> Character Analysis Preview</sub>
/

<sub> Visualised Abnormal Chars</sub>
### Enhanced Email Analysis
- **Improved URL Analysis**: 
  - Better suspicious TLD detection
  - IP address detection in URLs
  - Comprehensive URL obfuscation detection
  - Multiple encoding layer analysis
  - Keyword pattern matching in URLs
- **Character Encoding Detection**: Automatic detection and handling of various text encodings
- **Phishing Simulation Detection**: Identify potential training/awareness exercises
- **Business Context Detection**: Smart recognition of legitimate marketing services
### Advanced Risk Scoring System
- **Comprehensive Risk Assessment**: 100-point scoring system based on: 
  - Authentication failures (SPF/DKIM/DMARC)
  - Suspicious URLs and domains with obfuscation scoring
  - Character encoding anomalies and invisible character analysis
  - Content analysis with sophisticated keyword matching
  - Multi-vector attack correlation detection
- **Business Context Awareness**: Risk adjustments for legitimate marketing emails
- **Sophisticated Spoof Detection**: Advanced detection for valid authentication + phishing indicators
- **Visual Risk Indicators**: Colour-coded risk levels (Critical/High/Medium/Low)
- **Detailed Risk Breakdown**: Organised sections showing score components and correlations
- **Critical Indicators**: Highlighted severe threats requiring immediate attention
![image](https://github.com/user-attachments/assets/3f1a4e7f-7ea9-487f-ba0e-f77a7f79d378)

<sub> Colour coded overview, details (some details redacted as this was a real phishing email</sub>
### New in v2.1: Confidence Analysis System
- **Risk Confidence Scoring**: Statistical confidence assessment for risk predictions
- **Component-Level Confidence**: Individual confidence scores for each analysis component
- **Confidence Levels**: Five-tier system (Very Low → Very High) with business context awareness
![image](https://github.com/user-attachments/assets/fd2c0bf9-cd14-4abb-9539-1b047e53f517)

<sub> Confidence analysis preview
- **Intelligent Adjustments**: Reduced confidence for legitimate services with tracking elements
### Enhanced Keyword Analysis
- **Configurable Keyword Categories**: Six categories with customisable weights:
  - Common phishing phrases
  - Financial-related terms
  - Urgency and pressure tactics
  - Security-related scams
  - Too good to be true offers
  - Adult/Gaming content
- **Context-Aware Matching**: Keywords tracked separately in subject and body
- **Visual Highlighting**: Suspicious keywords highlighted in red within email content
- **Detailed Reporting**: Show exact keyword counts and locations
![image](https://github.com/user-attachments/assets/6d81916f-03bb-4fc0-9d5a-99b17972d0d6)
<sub> Keyword overview </sub>
![image](https://github.com/user-attachments/assets/b17cdac1-4b56-4781-9029-b3f6dcadf637)
<sub> Location, body highlighting capacity (some redaction) </sub>
### Improved User Experience
- **Enhanced Visual Output**: 
  - Colour-coded sections and warnings with emoji indicators
  - Professional formatting with banners and sections
  - Better truncation handling with --no-truncate option
  - Organised risk assessment with clear hierarchy
- **Verbose Mode**: Detailed header analysis and complete URL listings when needed
- **Better Error Handling**: More informative error messages and fallback mechanisms
- **Keyword File Management**: Built-in keyword file creation and management
## Technical Improvements
- **Modular Architecture**: Clean separation of concerns with dedicated modules
- **Robust Email Parsing**: Enhanced handling of both .msg and .eml files
- **Advanced URL Decoding**: 
  - Microsoft SafeLinks decoding
  - Multi-layer URL obfuscation detection
  - Base64 and URL encoding analysis
- **Multi-format Support**: Improved handling of HTML and plain text content
- **Character Set Detection**: Automatic encoding detection with confidence scoring
- **Business Context Engine**: Intelligent detection of legitimate marketing services
## Usage Remains Simple
```bash
# Analyse any email file
python3 wtp.py -msg path/to/email.msg
# Verbose output with full headers and all URLs
python3 wtp.py -msg path/to/email.eml -v
# Show full content without truncation
python3 wtp.py -msg path/to/email.msg --no-truncate
# Create default keyword files
python3 wtp.py --create-keywords
```
## What's Changed in v2.1
- **Business Context Detection**: Automatic recognition of legitimate marketing services with risk adjustment
- **Confidence Analysis**: Statistical confidence scoring for all risk assessments
- **Enhanced Correlation Analysis**: Multi-vector attack detection with business context awareness
- **Improved Character Analysis**: More granular invisible character detection and categorisation
- **Advanced URL Analysis**: Enhanced obfuscation detection with encoding layer tracking
- **Sophisticated Spoof Detection**: Better detection of legitimate authentication + phishing content
- **Keyword System Overhaul**: Configurable categories with visual highlighting and context tracking
## Updates for v2.2 inbound
- **Adding support for ExchangeOnline Quarantine management**
- **Advanced attachment analysis capabilities**

This project was made with ❤️ by Cylaris
