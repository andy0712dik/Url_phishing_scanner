import re

# List of common phishing keywords (for demonstration purposes)
phishing_keywords = ["login", "verify", "account", "update", "secure", "bank", "password", "signin", "confirm", "0"]

# Function to check if a URL contains phishing keywords
def contains_phishing_keywords(url):
    for keyword in phishing_keywords:
        if keyword in url.lower():
            return True
    return False

# Function to check if a URL contains suspicious patterns (e.g., IP addresses)
def contains_suspicious_patterns(url):
    # Check for presence of IP address in URL
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    if ip_pattern.search(url):
        return True

    # Check for multiple subdomains (e.g., http://secure-login.example.com)
    subdomain_pattern = re.compile(r'(\w+\.){3,}')
    if subdomain_pattern.search(url):
        return True

    return False

# Function to load known phishing domains from a .txt file
def load_known_phishing_domains(filename="C:/Users/Nihal/Downloads/phishing-domains-ACTIVE.txt"):
    try:
        with open(filename, 'r') as file:
            # Read lines and strip whitespace
            domains = {line.strip() for line in file if line.strip()}
        return domains
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        return set()

# Function to get a domain from user input
def get_user_input_domain():
    domain = input("Please enter the domain you want to check: ")
    return domain

# Main function to scan a domain for phishing
def scan_for_phishing(domain, known_phishing_domains):
    if domain in known_phishing_domains:
        print(f"Known phishing URL detected: {domain}")
    elif contains_phishing_keywords(domain):
        print(f"Potential phishing URL detected: {domain}")
    elif contains_suspicious_patterns(domain):
        print(f"Suspicious URL detected: {domain}")
    else:
        print(f"URL seems safe: {domain}")

# Example usage
if __name__ == "__main__":
    known_phishing_domains = load_known_phishing_domains()  # Load known phishing domains
    user_domain = get_user_input_domain()  # Get domain from user input
    scan_for_phishing(user_domain, known_phishing_domains)  # Scan the entered domain
