# Url_phishing_scanner


## Overview

The Phishing Link Scanner is a simple Python script that checks user-entered domains against a list of known phishing domains and identifies potential phishing indicators based on common keywords and suspicious patterns.

## Features

- Checks for common phishing keywords in the URL.
- Detects suspicious patterns, such as IP addresses and multiple subdomains.
- Loads known phishing domains from a specified text file.
- Interactive command-line interface for user input.

## Requirements

- Python 3.x

## Installation

1. Clone the repository or download the source code.
2. Create a text file named `phishing-domains-ACTIVE.txt` in the specified directory (e.g., `C:/Users/Nihal/Downloads/`) and populate it with known phishing domains, one per line.
3. Ensure you have Python 3.x installed on your system.

## Usage

1. Open a terminal or command prompt.
2. Navigate to the directory where the script is saved.
3. Run the script using the following command:

   ```bash
   python phishing_link_scanner.py
