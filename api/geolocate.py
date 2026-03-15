import json
import time
import requests
import socket
from urllib.parse import urlparse
import concurrent.futures

def get_domain(url):
    try:
        return urlparse(url).netloc.split(':')[0]
    except:
        return ""

def _resolve(domain):
    try:
        return domain, socket.gethostbyname(domain)
    except Exception:
        return domain, None

def main():
    print("Loading botnet_zombies.json...")
    with open("../botnet_zombies.json", "r") as f:
        data = json.load(f)
    
    print(f"Loaded {len(data)} items.")
    
    domains_to_lookup = []
    
    for item in data:
        domain = get_domain(item.get("url", ""))
        if domain:
            domains_to_lookup.append(domain)
    
    domains_to_lookup = list(set(domains_to_lookup))
    print(f"Unique domains to lookup: {len(domains_to_lookup)}")
    
    domain_to_ip = {}
    print("Resolving domains to IPs...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for domain, ip in executor.map(_resolve, domains_to_lookup):
            if ip:
                domain_to_ip[domain] = ip
                
    print(f"Resolved {len(domain_to_ip)} domains to IPs.")
    
    # We will only query unique IPs to save requests
    unique_ips = list(set(domain_to_ip.values()))
    print(f"Unique IPs to geolocate: {len(unique_ips)}")
    
    batch_size = 100
    ip_results = {}
    
    for i in range(0, len(unique_ips), batch_size):
        batch = list(unique_ips)[i:i+batch_size]
        print(f"Querying batch {i//batch_size + 1}/{len(unique_ips)//batch_size + 1}...")
        
        try:
            resp = requests.post("http://ip-api.com/batch", json=batch, timeout=10)
            if resp.status_code == 200:
                batch_results = resp.json()
                for res in batch_results:
                    if res.get("status") == "success":
                        ip = res.get("query")
                        ip_results[ip] = res
            else:
                print(f"Error {resp.status_code}")
        except Exception as e:
            print(f"Exception: {e}")
            
        time.sleep(4) 
        
    print(f"Successfully geolocated {len(ip_results)} IPs.")
    
    geo_data = []
    for item in data:
        domain = get_domain(item.get("url", ""))
        ip = domain_to_ip.get(domain)
        geo = ip_results.get(ip)
        if geo:
            item["lat"] = geo.get("lat")
            item["lon"] = geo.get("lon")
            item["country"] = geo.get("country")
            item["city"] = geo.get("city")
            item["ip"] = ip
            geo_data.append(item)
        
    with open("botnet_geo.json", "w") as f:
        json.dump(geo_data, f, indent=2)
    print(f"Saved {len(geo_data)} items to botnet_geo.json")

if __name__ == "__main__":
    main()
