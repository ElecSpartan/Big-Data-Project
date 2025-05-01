import csv
import ipaddress
import re
from urllib.parse import urlparse
from multiprocessing import Pool, cpu_count

def is_valid_ip(netloc):
    """Check if the network location contains a valid IP address"""
    # Handle IPv6 addresses with ports (e.g., [::1]:8080)
    if netloc.startswith('['):
        end = netloc.find(']')
        if end != -1:
            ip_part = netloc[1:end]
            port_part = netloc[end+1:]
            try:
                ipaddress.ip_address(ip_part)
                return True
            except ValueError:
                pass

    # Split host and port
    parts = netloc.split(':', 1)
    host = parts[0]

    # Handle IPv6 without brackets
    if re.match(r'^[a-fA-F0-9:]+$', host):
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass

    # Handle IPv4 addresses
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    return False

def check_double_slash_position(url):
    if url.startswith('http://'):
        protocol_end = 7
    elif url.startswith('https://'):
        protocol_end = 8
    else:
        protocol_end = 0

    positions = []
    start = 0
    while True:
        idx = url.find('//', start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 2

    if not positions:
        return 0

    for pos in positions:
        if protocol_end == 0:
            return 1
        else:
            if pos == protocol_end - 2:
                continue
            else:
                return 1
    return 0

def process_row(row):
    url = row.get('URL', '').strip()
    label = row.get('Label', '').strip()  # Get the original Label column
    status = "Success"  # Default status

    if not url:
        status = "Error: Empty URL"
        return {'URL': url, 'Status': status, 'Label': label}

    try:
        # Handle URLs without protocol
        if not url.startswith(('http://', 'https://')):
            parsed = urlparse('http://' + url)
        else:
            parsed = urlparse(url)

        # Extract domain information
        netloc = parsed.netloc
        domain = netloc.split(':')[0]  # Remove port if present

        # Skip invalid domains
        if not domain or not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            status = "Error: Invalid domain format"
            return {'URL': url, 'Status': status, 'Label': label}

        # Feature calculations
        have_ip = 1 if is_valid_ip(netloc) else 0
        have_at = 1 if '@' in url else 0

        # Handle empty or invalid 'url_length'
        url_length_str = row.get('url_length', '').strip()
        url_length = int(url_length_str) if url_length_str.isdigit() else 0
        url_length_over_54 = 1 if url_length > 54 else 0

        url_depth = parsed.path.count('/')
        redirect = check_double_slash_position(url)
        http_in_domain = 1 if 'http' in domain.lower() else 0
        https_in_domain = 1 if 'https' in domain.lower() else 0
        prefix_suffix_dash = 1 if domain.startswith('-') or domain.endswith('-') else 0
        
        # Handle empty or invalid 'dns_records'
        dns_records_str = row.get('dns_records', '').strip()
        dns_record = int(dns_records_str) if dns_records_str.isdigit() else 0
        
        # Handle empty or invalid 'domain_age'
        domain_age_str = row.get('domain_age', '').strip()
        domain_age = int(domain_age_str) if domain_age_str.isdigit() else -1
            
        domain_age_phishing = 1 if (domain_age != -1 and domain_age < 12) else 0
        subdomains_phishing = 1 if domain.count('.') > 3 else 0

        return {
            'URL': url,
            'Status': status,
            'Label': label,  # Include the original Label column
            'Domain': domain,
            'Have_IP': have_ip,
            'Have_At': have_at,
            'URL_Length_Over_54': url_length_over_54,
            'URL_Depth': url_depth,
            'Redirect_//_Position': redirect,
            'HTTP_In_Domain': http_in_domain,
            'HTTPS_In_Domain': https_in_domain,
            'Prefix_Suffix_Dash': prefix_suffix_dash,
            'DNS_Record': dns_record,
            'Domain_Age_Phishing': domain_age_phishing,
            'Subdomains_Phishing': subdomains_phishing
        }
    
    except Exception as e:
        status = f"Error: {str(e)}"
        return {'URL': url, 'Status': status, 'Label': label}

def main():
    input_file = 'output_cleaned.csv'
    output_file = 'features_extracted.csv'
    
    with open(input_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Use all available cores but limit to 12 as requested
    num_cores = min(12, cpu_count())
    
    with Pool(num_cores) as pool:
        results = pool.map(process_row, rows)

    # Filter out None results from failed processing
    valid_results = [res for res in results if res is not None]

    fieldnames = [
        'URL', 'Status', 'Label', 'Domain', 'Have_IP', 'Have_At', 'URL_Length_Over_54',
        'URL_Depth', 'Redirect_//_Position', 'HTTP_In_Domain',
        'HTTPS_In_Domain', 'Prefix_Suffix_Dash', 'DNS_Record',
        'Domain_Age_Phishing', 'Subdomains_Phishing'
    ]

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(valid_results)

if __name__ == '__main__':
    main()