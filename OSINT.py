import requests
import optparse
import json

def analyze_domain(domain):
    with open('.env.txt', 'r') as f:
        API_KEY = f.readline().strip()
    url = "https://app.netlas.io/api/host/" + domain
    query = domain
    headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
    }
    params = {
    "query": query,  
    }
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        results = response.json()  
        return results
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def get_domain():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-d", "--domain", dest="domain", help="Enter the domain name")
    (options, arguments) = parse_object.parse_args()
    return options.domain

def categorize_data(data):
    if data is None:
        return None
    else:
        whois = data.get('whois', {})
        categorized_data = {
            "Whois Information": {
                "Domain": whois.get("domain"),
                "Registrar Name": whois.get("registrar", {}).get("name"),
                "Registrar Email": whois.get("registrar", {}).get("email"),
                "Registrar Phone": whois.get("registrar", {}).get("phone"),
                "Registrar Referral URL": whois.get("registrar", {}).get("referral_url"),
                "WHOIS Server": whois.get("whois_server"),
                "Created Date": whois.get("created_date"),
                "Updated Date": whois.get("updated_date"),
                "Expiration Date": whois.get("expiration_date"),
                "Name Servers": whois.get("name_servers", []),
                "Status": whois.get("status", [])
            },
            "DNS Records": {
                "A Records": data.get("dns", {}).get("a", []),
                "MX Records": data.get("dns", {}).get("mx", []),
                "TXT Records": data.get("dns", {}).get("txt", []),
                "NS Records": data.get("dns", {}).get("ns", [])
            },
            "Related Domains": {
                "Count": data.get("related_domains_count", 0),
                "Domains": data.get("related_domains", [])
            }
        }
        return categorized_data
try:
    print("Welcome OSINT")
    print("Please wait while we analyze the domain...")
    print("Analyzing the domain...")
    domain = get_domain()
    analyze_domain = analyze_domain(domain)
    print(categorize_data(analyze_domain))
except Exception as e:
    print("Please enter a valid domain. Example: -d google.com")