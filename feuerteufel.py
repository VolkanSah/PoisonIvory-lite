from scapy.all import *
from stem import Signal
from stem.control import Controller
import requests
import re

# Get onion address from monitoring script loaded before
onion_address = "INSERT .ONION ADDRESS HERE"  # .onion address you want to monitor

# Set controller
with Controller.from_port(port=9051) as controller:
    controller.authenticate()

# Set Stream Listener
class MaliciousTrafficListener(StreamListener):
    def __init__(self, keywords):
        self.keywords = keywords

    def stream_new(self, stream):
        if any(re.search(keyword, stream.target_host) for keyword in self.keywords):
            print(f"Malicious traffic detected to {stream.target_host}")

# Register the Stream Listener
with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    listener = MaliciousTrafficListener(["bad", "badsite"])
    controller.add_event_listener(listener)

    input("Press Enter to exit")

def check_if_tor_traffic(packet):
    """
    Check if the packet belongs to Tor traffic.

    Args:
        packet: The packet to be checked.

    Returns:
        True if the packet belongs to Tor traffic, False otherwise.
    """
    if packet.haslayer(TCP) and packet[TCP].dport == 443:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            if controller.get_info("address") == packet[IP].dst:
                return True
    return False

def intercept_api_requests(request):
    """
    Intercept API requests and execute an external script.

    Args:
        request: The intercepted API request.
    """
    if sniff_packets():
        # This is where you would load and execute your external script.
        # Remember that executing code fetched from the internet can be risky.
        external_script_url = "https://example.com/external_script.py"
        response = requests.get(external_script_url)
        if response.status_code == 200:
            exec(response.text)
        else:
            print("Failed to load the external script.")

def sniff_packets():
    """
    Sniff packets and filter for Tor traffic.

    Returns:
        The sniffed packets.
    """
    packets = sniff(filter="tcp and (port 9050 or port 9051)", prn=check_if_tor_traffic)

    return packets

def get_circuit_hops():
    """
    Get the current circuit and its hops.

    Returns:
        The circuit hops.
    """
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        circuit_id = controller.get_circuit_id()
        hops = controller.get_circuit(circuit_id).path

    return hops

def exclude_malicious_relays():
    """
    Add malicious relays to the circuit blacklist.
    """
    hops = get_circuit_hops()
    malicious_relays = ["FINGERPRINT1", "FINGERPRINT2"]  # Add the fingerprints of malicious relays

    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        for hop in hops:
            if hop.fingerprint in malicious_relays:
                controller.set_conf(f"ExcludeExitNodes {hop.fingerprint}")

# Example usage
exclude_malicious_relays()
