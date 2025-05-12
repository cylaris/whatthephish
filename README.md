![image](https://github.com/user-attachments/assets/961e196d-ddbc-4034-832a-2f18fa7b3682)

## WhatThePhish v2.0

A significantly enhanced email phishing analysis tool with advanced character analysis and evasion detection capabilities.

![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![Language](https://img.shields.io/badge/Language-Python-blue)
![License](https://img.shields.io/badge/License-MIT-green)

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
  - Invisible/zero-width characters
  - Mixed script detection
  - Suspicious Unicode ranges
- **Character Spacing Evasion**: Detection of artificial spacing and formatting tricks
- **Visual Flagging**: Characters highlighted in red when suspicious patterns detected

![image](https://github.com/user-attachments/assets/1032aa12-096f-4402-bfcc-71751a96ae67)
<sub> Character Analysis Preview</sub>

![image](https://github.com/user-attachments/assets/b996c19b-d881-48e5-b7ba-3b17438e8792)
<sub> Visualised Abnormal Chars</sub>


### Enhanced Email Analysis
- **Improved URL Analysis**: 
  - Better suspicious TLD detection
  - IP address detection in URLs
  - URL length analysis
  - Keyword pattern matching
- **Character Encoding Detection**: Automatic detection and handling of various text encodings
- **Phishing Simulation Detection**: Identify potential training/awareness exercises

### Risk Scoring System (Currently in Alpha)
- **Comprehensive Risk Assessment**: 100-point scoring system based on: 
  - Authentication failures (SPF/DKIM/DMARC)
  - Suspicious URLs and domains
  - Character encoding anomalies
  - Content analysis
- **Visual Risk Indicators**: Colour-coded risk levels (High/Medium/Low)
- **Detailed Risk Factors**: Specific explanation of score contributors

![image](https://github.com/user-attachments/assets/ea3e3fcd-5060-4b5e-8a43-0fae1f550ee9)
<sub> Colour coded overview, details (some details redacted as this was a real phishing email</sub>

### Improved User Experience
- **Enhanced Visual Output**: 
  - Colour-coded sections and warnings
  - Professional formatting with banners and sections
  - Better truncation handling with --no-truncate option
- **Verbose Mode**: Detailed header analysis when needed
- **Better Error Handling**: More informative error messages and fallback mechanisms

## Technical Improvements

- **Robust Email Parsing**: Better handling of both .msg and .eml files
- **SafeLinks Decoding**: Automatic Microsoft SafeLinks URL decoding
- **Multi-format Support**: Improved handling of HTML and plain text content
- **Character Set Detection**: Automatic encoding detection with chardet library

## Updates for v2.1 inbound
- **Adding support for ExchangeOnline Quarantine management**

## Usage Remains Simple

```bash
# Analyse any email file
python3 wtp.py -msg path/to/email.msg

# Verbose output with full headers
python3 wtp.py -msg path/to/email.eml -v

# Show full content without truncation
python3 wtp.py -msg path/to/email.msg --no-truncate
```
