from scapy.all import sniff, IP, TCP, UDP, ICMP
import requests
import json
import uuid
import time
from datetime import datetime
import threading 
import platform 

# Flask API endpoint for receiving real-time data
FLASK_API_URL = "http://127.0.0.1:5000/realtime_data"
FLASK_SESSION_END_URL = "http://127.0.0.1:5000/session_end"

# Generate a unique session ID for this sniffing instance
SESSION_ID = str(uuid.uuid4())
print(f"Sniffer session ID for current run: {SESSION_ID}")

# Flag to control sniffing
sniffing_active = True

# Removed GeoIP related imports and functions (geoip2.database, get_location_from_ip)

def parse_packet(packet):
    """Parses a Scapy packet object and extracts relevant details."""
    packet_info = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], 
        'source_ip': 'N/A',
        'destination_ip': 'N/A',
        'protocol': 'N/A',
        'source_port': 'N/A',
        'destination_port': 'N/A',
        'length': len(packet),
        'flags': 'N/A',
        'event_type': None, 
        'alert_signature': None 
    }

    if IP in packet:
        packet_info['source_ip'] = packet[IP].src
        packet_info['destination_ip'] = packet[IP].dst
        packet_info['ttl'] = packet[IP].ttl

    if TCP in packet:
        packet_info['protocol'] = 'TCP'
        packet_info['source_port'] = packet[TCP].sport
        packet_info['destination_port'] = packet[TCP].dport
        packet_info['flags'] = str(packet[TCP].flags)
    elif UDP in packet:
        packet_info['protocol'] = 'UDP'
        packet_info['source_port'] = packet[UDP].sport
        packet_info['destination_port'] = packet[UDP].dport
    elif ICMP in packet:
        packet_info['protocol'] = 'ICMP'
        packet_info['type'] = packet[ICMP].type
        packet_info['code'] = packet[ICMP].code

    return packet_info

def send_packet_to_flask(packet_info):
    """
    Sends parsed packet data to the Flask application for analysis and dashboard updates.
    Includes simple rule-based detection for SSH_ATTEMPT.
    """
    payload = {
        'session_id': SESSION_ID,
        'prediction': "Normal Traffic", 
        'attack_type': None, 
        'details': {}, 
        'src_location': {}, # src_location will now always be empty since GeoIP is removed
        'raw_packet_data': packet_info 
    }

    # Rule-Based Attack Type Detection for specific charts (like SSH_ATTEMPT)
    if packet_info['protocol'] == 'TCP' and packet_info['destination_port'] == 22: # SSH port
        payload['attack_type'] = "SSH_ATTEMPT"
        payload['event_type'] = "Potential SSH Activity" 
        payload['alert_signature'] = "SSH_PORT_ACCESS" 
    elif packet_info['protocol'] == 'UDP' and packet_info['destination_port'] in [53, 161]: # Common UDP ports like DNS, SNMP
        # This is a very basic example; more complex rules would be needed for true UDP flood
        # For demonstration, we can broadly label high volume UDP as potential flood
        # if the ML model later classifies it as 'Attack'.
        # For now, we only apply this if it's UDP and a common port.
        payload['attack_type'] = "UDP_FLOOD" # You can categorize general UDP floods like this
        payload['event_type'] = "Potential UDP Flood Activity"
        payload['alert_signature'] = "UDP_HIGH_PORT_ACTIVITY"

    try:
        response = requests.post(FLASK_API_URL, json=payload, timeout=1)
        response.raise_for_status() 
        # print(f"Packet sent to Flask. Status: {response.status_code}") # Uncomment for detailed packet-by-packet confirmation
    except requests.exceptions.Timeout:
        print("Warning: Request to Flask timed out. Is Flask app running?")
    except requests.exceptions.ConnectionError:
        print("Warning: Could not connect to Flask app. Is Flask app running at 127.0.0.1:5000?")
    except requests.exceptions.RequestException as e:
        print(f"Error sending data to Flask: {e}")

def packet_callback(packet):
    """Callback function for each sniffed packet."""
    if not sniffing_active:
        return

    packet_info = parse_packet(packet)
    send_packet_to_flask(packet_info)

def stop_sniffing():
    """Stops the sniffing process and sends session end signal to Flask."""
    global sniffing_active
    sniffing_active = False
    print("\nAttempting to stop sniffing...")
    try:
        response = requests.post(FLASK_SESSION_END_URL, json={'session_id': SESSION_ID})
        response.raise_for_status()
        print(f"Session end signal sent to Flask successfully. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending session end signal to Flask: {e}")
    
    # Removed geoip_reader.close()
    print("Sniffer process finished.")

# Removed get_network_interfaces() function

if __name__ == "__main__":
    print("Starting real-time network sniffer...")
    print("Ensure Flask app is running at http://127.0.0.1:5000")
    print("Press Ctrl+C to stop sniffing and send session end signal.")
    
    # Scapy will auto-select an interface if iface=None (default behavior)
    # This often works for the primary active interface on the host machine.
    # If it fails, you might need to manually set iface to a known working name
    # like 'Ethernet' or 'Wi-Fi' directly here:
    # sniff_thread = threading.Thread(target=sniff, kwargs={'prn': packet_callback, 'store': 0, 'iface': 'Wi-Fi'})
    
    print("\nAttempting to sniff on an auto-detected interface...")
    sniff_thread = threading.Thread(target=sniff, kwargs={'prn': packet_callback, 'store': 0, 'iface': None})
    sniff_thread.daemon = True 
    sniff_thread.start()

    try:
        while True:
            time.sleep(1) 
    except KeyboardInterrupt:
        pass 
    finally:
        stop_sniffing() 
        if sniff_thread.is_alive():
            print("Waiting for sniffing thread to terminate...")
            sniff_thread.join(timeout=2) 
        print("Sniffer script exited.")



