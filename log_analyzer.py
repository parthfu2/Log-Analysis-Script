import re
from collections import defaultdict
import csv


def analyze_log(log_file):
    ip_requests = defaultdict(int)
    endpoint_access = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(log_file, "r") as file:
        for line in file:
            # Extract IP address
            ip = line.split()[0]
            ip_requests[ip] += 1

            # Extract endpoint
            match = re.search(r'"GET|POST ([^ ]+)', line)
            if match:
                endpoint = match.group(1)
                endpoint_access[endpoint] += 1

            # Check for failed logins
            if "POST /login" in line and "401" in line:
                failed_logins[ip] += 1

    return ip_requests, endpoint_access, failed_logins


def print_results(ip_requests, endpoint_access, failed_logins):
    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    most_accessed = max(endpoint_access, key=endpoint_access.get)
    print(f"{most_accessed} (Accessed {endpoint_access[most_accessed]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in failed_logins.items():
        if count > 2:  # Threshold set to 2 for demonstration purposes
            print(f"{ip:<20} {count}")


def save_to_csv(ip_requests, endpoint_access, failed_logins):
    with open("log_analysis_results.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        most_accessed = max(endpoint_access, key=endpoint_access.get)
        writer.writerow([most_accessed, endpoint_access[most_accessed]])

        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            if count > 2:  # Threshold set to 2 for demonstration purposes
                writer.writerow([ip, count])


# Main execution
log_file = "sample.log"
ip_requests, endpoint_access, failed_logins = analyze_log(log_file)
print_results(ip_requests, endpoint_access, failed_logins)
save_to_csv(ip_requests, endpoint_access, failed_logins)
