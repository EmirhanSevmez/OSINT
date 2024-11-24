import requests
import optparse
import json

def analyze_domain(domain): # Function to analyze a domain using Netlas API
    with open('.env.txt', 'r') as f: # Read API key from .env.txt file
        API_KEY = f.readline().strip()
    url = "https://app.netlas.io/api/host/" + domain # API endpoint
    query = domain # Query to search for
    headers = { 
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
    }
    params = {
    "query": query,  
    }
    response = requests.get(url, headers=headers, params=params) # Make a GET request to the API endpoint

    if response.status_code == 200: # If the request is successful
        results = response.json()    # Parse the JSON response
        return results # Return the results
    else: # If the request is not successful
        print(f"Error: {response.status_code} - {response.text}") # Print the error message
        return None # Return None

def get_domain(): # Function to get the domain name from the user
    parse_object = optparse.OptionParser() # Create an OptionParser object
    parse_object.add_option("-d", "--domain", dest="domain", help="Enter the domain name") # Add an option to the OptionParser object
    (options, arguments) = parse_object.parse_args() # Parse the command line arguments
    return options.domain # Return the domain name

def categorize_data(data): # Function to categorize the data
    if data is None: # If the data is None
        return None # Return None
    else: # If the data is not None
        whois = data.get('whois', {}) # Get the whois data from the data
        categorized_data = { # Create a dictionary to store the categorized data
            "Whois Information": { # Create a dictionary to store the whois information
                "Domain": whois.get("domain"), # Get the domain name from the whois data
                "Registrar Name": whois.get("registrar", {}).get("name"), # Get the registrar name from the whois data
                "Registrar Email": whois.get("registrar", {}).get("email"), # Get the registrar email from the whois data
                "Registrar Phone": whois.get("registrar", {}).get("phone"), # Get the registrar phone from the whois data
                "Registrar Referral URL": whois.get("registrar", {}).get("referral_url"), # Get the registrar referral URL from the whois data
                "WHOIS Server": whois.get("whois_server"), # Get the WHOIS server from the whois data
                "Created Date": whois.get("created_date"), # Get the created date from the whois data
                "Updated Date": whois.get("updated_date"), # Get the updated date from the whois data
                "Expiration Date": whois.get("expiration_date"), # Get the expiration date from the whois data
                "Name Servers": whois.get("name_servers", []), # Get the name servers from the whois data
                "Status": whois.get("status", []) # Get the status from the whois data
            },
            "DNS Records": { # Get the DNS records from the whois data
                "A Records": data.get("dns", {}).get("a", []), # Get the A records from the DNS data
                "MX Records": data.get("dns", {}).get("mx", []), # Get the MX records from the DNS data
                "TXT Records": data.get("dns", {}).get("txt", []), # Get the TXT records from the DNS data
                "NS Records": data.get("dns", {}).get("ns", []) # Get the NS records from the DNS data
            },
            "Related Domains": { # Get the related domains from the whois data
                "Count": data.get("related_domains_count", 0), # Get the count of related domains from the whois data
                "Domains": data.get("related_domains", []) # Get the related domains from the whois data
            }
        }
        return categorized_data # Return the categorized data
try:
    print("Welcome OSINT") # Welcome message
    print("Please wait while we analyze the domain...") # Wait message
    print("Analyzing the domain...") # Analyzing message
    domain = get_domain() # Get the domain from the user
    analyze_domain = analyze_domain(domain) # Analyze the domain
    print(categorize_data(analyze_domain)) # Print the categorized data
except: # If there is an error
    print("Please enter a valid domain. Example: -d google.com") # Print the error message
