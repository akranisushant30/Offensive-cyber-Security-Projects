import socket                       # Networking ke liye socket module
import concurrent.futures            # Multi-threading ke liye (fast scan)
import sys                           # Console output control ke liye (progress bar)

# --- Colors for output ---
RED = "\033[91m"                    # Red color (Open ports highlight)
GREEN = "\033[92m"                  # Green color (Banner text)
RESET = "\033[0m"                   # Reset color to normal    
# -------------------------------
# Function: Format Results Output
# -------------------------------
def format_port_results(results):
    formatted_results = "Port Scan Results:\n"
    formatted_results += "{:<8} {:<6} {:<15} {:<10}\n".format("Port", "Proto", "Service", "Status")
    formatted_results += '-' * 85 + "\n"
    
    # Har port ke result ko format kar ke print karta hai
    for port, proto, service, banner, status in results:
        status_text = "Open" if status else "Closed/Filtered"
        if status:
            formatted_results += f"{RED}{port:<8} {proto:<6} {service:<15} {status_text:<10}{RESET}\n"
            if banner:
                banner_lines = banner.split('\n')
                for line in banner_lines:
                    formatted_results += f"{GREEN}{'':<8}{line}{RESET}\n"
    return formatted_results
# --------------------------
# Function: Get Banner (TCP)
# --------------------------
def get_banner(sock):
    try:
        sock.settimeout(1)          # 1 second timeout for banner grab
        banner = sock.recv(1024).decode().strip()  # Service ka banner data lena
        return banner
    except:
        return ""                   # Agar kuch nahi mila toh blank return karo
# ------------------------
# Function: Scan TCP Port
# ------------------------
def scan_tcp_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket bnao
        sock.settimeout(10)                                        # 1s timeout
        result = sock.connect_ex((target_ip, port))               # Port connection test karo
        if result == 0:
            try:
                service = socket.getservbyport(port, 'tcp')       # Port ka service name
            except:
                service = 'Unknown'
            banner = get_banner(sock)                             # Banner grab karo
            return port, "TCP", service, banner, True              # Port open mila
        else:
            return port, "TCP", "", "", False                     # Port closed
    except:
        return port, "TCP", "", "", False
    finally:
        sock.close()                                              # Socket close karna jaruri
# ------------------------
# Function: Scan UDP Port
# ------------------------
def scan_udp_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # UDP socket bnao
        sock.settimeout(10)                                        # 1s timeout
        sock.sendto(b"", (target_ip, port))                       # Empty datagram bhejo
        try:
            data, _ = sock.recvfrom(1024)                         # Response milta hai kya check karo
            return port, "UDP", "Possible Open", data.decode(errors="ignore"), True
        except socket.timeout:                                    # Agar response nahi mila
            return port, "UDP", "No Response", "", False          # UDP mai "open|filtered" ho sakta hai
    except Exception as e:
        return port, "UDP", "", "", False
    finally:
        sock.close()
# ---------------------------
# Function: Main Port Scanner
# ---------------------------
def port_scan(target_host, start_port, end_port, scan_udp=False):
    target_ip = socket.gethostbyname(target_host)                 # Hostname → IP
    print(f"Starting scan on host: {target_ip}\n")

    results = []                                                  # Final results store karne ke liye
    total_ports = end_port - start_port + 1                       # Kitne ports scan hone wale hai
    max_workers = min(200, total_ports)                           # Thread limit adjust karo

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []

        # TCP scanning jobs submit karo
        for port in range(start_port, end_port + 1):
            futures.append(executor.submit(scan_tcp_port, target_ip, port))

        # Agar UDP scanning bhi on hai toh uske jobs bhi
        if scan_udp:
            for port in range(start_port, end_port + 1):
                futures.append(executor.submit(scan_udp_port, target_ip, port))

        # Progress bar + results collect karna
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            port, proto, service, banner, status = future.result()
            results.append((port, proto, service, banner, status))
            sys.stdout.write(f"\rProgress: {i}/{len(futures)} ports scanned")
            sys.stdout.flush()

    print("\n")
    results.sort(key=lambda x: (x[1], x[0]))                      # Sort by protocol & port
    print(format_port_results(results))                           # Final result print
# --------------------------
# Main Program Entry Point
# --------------------------
if __name__ == '__main__':
    target_host = input("Enter your target IP or domain: ")       # User se target IP/host lo
    start_port = int(input("Enter start port: "))                 # Starting port number
    end_port = int(input("Enter end port: "))                     # Ending port number
    udp_choice = input("Do you want to scan UDP ports too? (y/n): ").lower() == 'y'
    port_scan(target_host, start_port, end_port, udp_choice)      # Port scanner run karo
