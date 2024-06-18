# ThreatAnalyzer

ThreatAnalyzer is a Python-based tool designed to retrieve and analyze information about IP addresses, URLs, or hash files using the VirusTotal API. It fetches data such as reputation status, malicious scores, geographical information, and more, presenting the results in an Excel file for easy analysis and visualization.

## Features

- Supports analysis of IP addresses, URLs, and hash files.
- Utilizes VirusTotal API for retrieving detailed threat intelligence.
- Generates comprehensive Excel reports with graphical representations.
- Provides insights into geographical distribution, threat categories, and more.

## Requirements

- Python 3.8 or Latest
- Pandas
- Requests
- Openpyxl

## Installation

1. Clone the repository:
   git clone https://github.com/Machiaveliz/ThreatAnalyzer.git
   cd ThreatAnalyzer

2. Install dependencies
pip install -r requirements.txt

3. Obtain a VirusTotal API key from VirusTotal and update it in the main.py file.

## Usage
To analyze IP addresses, URLs, or hash files, run the script with appropriate arguments:
   - IP:
      python threatanalyzer.py -i ip.txt
   - URL:
      python threatanalyzer.py -u url.txt
   - Hash:
      python threatanalyzer.py -hf hash.txt
'''bash 
- -i: Specify a file containing IP addresses.
- -u: Specify a file containing URLs. *url must contain domain only, ex: www.google.com or google.com
- -hf: Specify a file containing hash files.
- -t: Set the threshold for considering an item malicious (default: 3).
- -o: Specify the name for the output Excel file (without extension).
'''

## Output
The tool generates an Excel report (output_report.xlsx) containing detailed analysis results, including:

- Status (Malicious or Not Malicious)
- Malicious Score
- ISP, Country, Continent
- Whois information (Address, Organization, Email, Phone)
- Charts illustrating geographical distribution and other metrics.

## Executive Summary
Each Excel report includes an "Executive Summary" sheet providing a high-level overview and mitigation strategies based on the analysis results.
