import requests
import base64
import os

# FOFA API credentials
FOFA_EMAIL = 'rootsmacksovh@gmail.com'
FOFA_KEY = '67b77219b02e04d6a6917b6e5244248b'

# ISO 3166-1 alpha-2 country codes (full list)
ALL_COUNTRY_PREFIXES = [
    "AF", "AX", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR", "AM", "AW", "AU", 
    "AT", "AZ", "BS", "BH", "BD", "BB", "BY", "BE", "BZ", "BJ", "BM", "BT", "BO", "BQ", 
    "BA", "BW", "BV", "BR", "IO", "BN", "BG", "BF", "BI", "CV", "KH", "CM", "CA", "KY", 
    "CF", "TD", "CL", "CN", "CX", "CC", "CO", "KM", "CG", "CD", "CK", "CR", "HR", "CU", 
    "CW", "CY", "CZ", "DK", "DJ", "DM", "DO", "EC", "EG", "SV", "GQ", "ER", "EE", "ET", 
    "FK", "FO", "FJ", "FI", "FR", "GF", "PF", "TF", "GA", "GM", "GE", "DE", "GH", "GI", 
    "GR", "GL", "GD", "GP", "GU", "GT", "GG", "GN", "GW", "GY", "HT", "HM", "VA", "HN", 
    "HK", "HU", "IS", "IN", "ID", "IR", "IQ", "IE", "IM", "IL", "IT", "JM", "JP", "JE", 
    "JO", "KZ", "KE", "KI", "KP", "KR", "KW", "KG", "LA", "LV", "LB", "LS", "LR", "LY", 
    "LI", "LT", "LU", "MO", "MG", "MW", "MY", "MV", "ML", "MT", "MH", "MQ", "MR", "MU", 
    "YT", "MX", "FM", "MD", "MC", "MN", "ME", "MS", "MA", "MZ", "MM", "NA", "NR", "NP", 
    "NL", "NC", "NZ", "NI", "NE", "NG", "NU", "NF", "MP", "NO", "OM", "PK", "PW", "PS", 
    "PA", "PG", "PY", "PE", "PH", "PN", "PL", "PT", "PR", "QA", "RE", "RO", "RU", "RW", 
    "BL", "SH", "KN", "LC", "MF", "PM", "VC", "WS", "SM", "ST", "SA", "SN", "RS", "SC", 
    "SL", "SG", "SX", "SK", "SI", "SB", "SO", "ZA", "GS", "SS", "ES", "LK", "SD", "SR", 
    "SJ", "SE", "CH", "SY", "TW", "TJ", "TZ", "TH", "TL", "TG", "TK", "TO", "TT", "TN", 
    "TR", "TM", "TC", "TV", "UG", "UA", "AE", "GB", "US", "UM", "UY", "UZ", "VU", "VE", 
    "VN", "VG", "VI", "WF", "EH", "YE", "ZM", "ZW", "US", "CN", "AU", "IN", "GB", "DE", "FR", "JP", "KR", "BR", 
    "RU", "ZA", "IT", "ES", "CA", "MX", "TR", "NL", "SE", "CH"
]

# Remove duplicates from the list
COUNTRY_PREFIXES = [code for code in ALL_COUNTRY_PREFIXES if code not in [
]]

def fofa_ips(query):
    base_url = 'https://fofa.info'
    search_url = f'{base_url}/api/v1/search/all'

    query_base64 = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    params = {
        'qbase64': query_base64,
        'email': FOFA_EMAIL,
        'key': FOFA_KEY,
        'size': 10000
    }

    try:
        response = requests.get(search_url, params=params)
        if response.status_code == 200:
            data = response.json()  # Fix indentation here
            ips = [result[0] for result in data['results']]
            return ips
        else:
            print(f"Failed to retrieve data for query {query}. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Request failed for query {query}: {e}")
        return []


def save_to_file(filename, ips):
    try:
        with open(filename, 'w') as file:
            for ip in ips:
                file.write(ip + '\n')
        print(f"IPs saved to {filename}")
    except IOError as e:
        print(f"Error writing to file {filename}: {e}")

if __name__ == "__main__":
    for country in COUNTRY_PREFIXES:
        query = f'"geoserver" && country="{country}"'
        filename = f"geo{country}.txt"

        print(f"Fetching IPs for country: {country}")
        ips = fofa_ips(query)

        if ips:
            save_to_file(filename, ips)
        else:
            print(f"No IPs found or error occurred for country: {country}")