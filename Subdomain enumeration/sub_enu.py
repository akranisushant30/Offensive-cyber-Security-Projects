import dns.resolver
import requests
import threading
import sys

lock = threading.Lock()
open('Found_subdomain.txt','w').close()
def get_dns_records(domain):
    records_type = ['A']
    resolver = dns.resolver.Resolver()
    dnsrecords = []
    for record_type in records_type:
        try:
            answers = resolver.resolve(domain,record_type)
            for ipadd in answers:
                dnsrecord = f'{record_type} : {ipadd}'
                dnsrecords.append(dnsrecord)
                print(dnsrecord)
        except dns.resolver.NoAnswer:
            continue
    return dnsrecords
def check_domain (subdomain,domain):
    host = f'{subdomain}.{domain}'
    url = f'http://{host}'
    try:
        response = requests.get(url,allow_redirects=True)
    except requests.ConnectionError:
        pass
    else:
        final_url = response.url
        print(f"Found Domain: {final_url}")
        records = get_dns_records(f'{subdomain}.{domain}')
        with lock:
            with open("Found_subdomain.txt",'a') as f:
                f.write(f'{final_url}\n')
                for record in records:
                    f.write(f'{record}\n')
    
def subdomain_enumeration(domain):
    with open("subdomains.txt",'r') as f:
        subdomains = f.read().splitlines()
    threads = []
    for subdomain in subdomains:
        thread = threading.Thread(target=check_domain,args=(subdomain,domain))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

domain = sys.argv[1]
subdomain_enumeration(domain)

