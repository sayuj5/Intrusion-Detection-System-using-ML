import requests
import os
import time

print("Attempting to connect to Google (google.com) via HTTPS...")
try:
    response = requests.get("https://www.google.com", timeout=10) # 10-second timeout
    response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
    print(f"Successfully connected to www.google.com! Status Code: {response.status_code}")
    print("Your Python environment has basic internet access.")
except requests.exceptions.Timeout:
    print("ERROR: Request to www.google.com timed out.")
    print("Possible issues: Slow internet, heavy network traffic, local firewall blocking outbound connections, or proxy issues.")
except requests.exceptions.RequestException as e:
    print(f"ERROR: Could not connect to www.google.com: {e}")
    print("Possible issues: DNS resolution failure, network unreachable, local firewall blocking outbound connections, or proxy issues.")

print("\nAttempting to connect directly to Google Cloud Firestore endpoint (firestore.googleapis.com)...")
try:
    # This is not a full Firestore API call, but a general check for the domain
    response = requests.get("https://firestore.googleapis.com", timeout=10)
    response.raise_for_status()
    print(f"Successfully connected to firestore.googleapis.com! Status Code: {response.status_code}")
    print("Your Python environment can reach the Firestore API domain.")
except requests.exceptions.Timeout:
    print("ERROR: Request to firestore.googleapis.com timed out.")
    print("This strongly suggests a firewall, proxy, or network routing issue preventing outbound connections to Google Cloud.")
except requests.exceptions.RequestException as e:
    print(f"ERROR: Could not connect to firestore.googleapis.com: {e}")
    print("This strongly suggests a firewall, proxy, or network routing issue preventing outbound connections to Google Cloud.")

print("\nAttempting a DNS lookup for firestore.googleapis.com (using os.system ping)...")
try:
    # Use os.system ping for a direct command line network test
    if os.name == 'nt': # For Windows
        command = "ping -n 1 firestore.googleapis.com"
    else: # For Linux/macOS
        command = "ping -c 1 firestore.googleapis.com"

    result = os.system(command)
    if result == 0:
        print("DNS lookup and ping to firestore.googleapis.com successful.")
    else:
        print("DNS lookup or ping to firestore.googleapis.com failed. Check DNS settings or network connectivity.")
except Exception as e:
    print(f"ERROR: Could not run ping command: {e}")

print("\nConnectivity tests complete.")