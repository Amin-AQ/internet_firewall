# firewall_app/management/commands/sniffer.py
from django.core.management.base import BaseCommand
import socket
from scapy.all import sniff, IP, TCP
import atexit

from firewall_app.models import FirewallLog
from .utils import compare_packet_against_rules
# Get the host IP address


class Command(BaseCommand):
    help = 'Run the packet sniffer'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Sniffer is running...'))
outer = []
def start_sniffer():
    global sniffer_handle      
    # Get a list of all IP addresses associated with the host
    host_ip_addresses = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")]

    print("Host IP Addresses:", host_ip_addresses)
    sessions = {}  
    def extract_features(packet):
        '''
        Function to process a packet and extract features, such as IP's, ports, bytes count, packets count
        '''
        features = {}
        # Extract Ethernet layer information
        #if packet.haslayer('Ethernet'):
        #    features['Src_MAC'] = packet['Ethernet'].src
        #    features['Dst_MAC'] = packet['Ethernet'].dst

        # Extract IP layer information
        if packet.haslayer('IP'):
            session_info={}
            has_transport_layer = False
            # Extract TCP layer information
            if packet.haslayer('TCP'):
                has_transport_layer =True
                features['protocol'] = 'tcp'
                src_port,dest_port,session_info = process_tcp_packet(packet,packet['IP'].src, packet['IP'].dst)
            elif packet.haslayer('UDP'):
                has_transport_layer = True
                features['protocol'] = 'udp'
                src_port,dest_port,session_info = process_udp_packet(packet,packet['IP'].src, packet['IP'].dst)
            
            if has_transport_layer== True:
                features['Src_IP'] = packet['IP'].src
                features['Src_Port'] = src_port
                features['Dest_IP'] = packet['IP'].dst
                features['Dest_Port'] = dest_port
                features['Session Info'] = session_info
                print(features, '\n\n')

                action_taken = compare_packet_against_rules(features)

                log_packet(features, action_taken)
            

    def process_tcp_packet(packet, src_ip, dest_ip):
        src_port = packet['TCP'].sport
        dest_port = packet['TCP'].dport
        tcp_flags = packet['TCP'].flags

        session_id = tuple(sorted((src_ip, str(src_port), dest_ip, str(dest_port))))

        if session_id not in sessions:
            sessions[session_id] = {'bytes_sent': 0,'bytes_received': 0,'total_bytes': 0, 'packet_count': 0}

        if packet.haslayer('Raw'):
            sessions[session_id]['total_bytes'] += len(packet['Raw'].load)
            if src_ip in host_ip_addresses:
                sessions[session_id]['bytes_sent'] += len(packet['Raw'].load)
            elif dest_ip in host_ip_addresses:
                sessions[session_id]['bytes_received'] += len(packet['Raw'].load)

        sessions[session_id]['packet_count'] += 1


        session_info = {
            'session_id': session_id,
            'bytes_sent': sessions[session_id]['bytes_sent'],
            'bytes_received': sessions[session_id]['bytes_received'],
            'total_bytes': sessions[session_id]['total_bytes'],
            'packet_count': sessions[session_id]['packet_count']
        }

        tcp_flags = packet['TCP'].flags

        # Check for TCP SYN and FIN flags to identify session start and end
        if tcp_flags & 0x02:  # Check if SYN flag is set
            session_info['event'] = 'TCP SYN flag detected - Session start'
        elif tcp_flags & 0x01:  # Check if FIN flag is set
            session_info['event'] = 'TCP FIN flag detected - Session end'
            # Remove session from dictionary when the TCP FIN flag is detected
            del sessions[session_id]

        return src_port,dest_port,session_info

    def process_udp_packet(packet, src_ip, dest_ip):
        src_port = packet['UDP'].sport
        dest_port = packet['UDP'].dport

        session_id = tuple(sorted((src_ip, str(src_port), dest_ip, str(dest_port))))

        if session_id not in sessions:
            sessions[session_id] = {'bytes_sent': 0,'bytes_received': 0,'total_bytes': 0, 'packet_count': 0}

        if packet.haslayer('Raw'):
            sessions[session_id]['total_bytes'] += len(packet['Raw'].load)
            if src_ip in host_ip_addresses:
                sessions[session_id]['bytes_sent'] += len(packet['Raw'].load)
            elif dest_ip in host_ip_addresses:
                sessions[session_id]['bytes_received'] += len(packet['Raw'].load)

        sessions[session_id]['packet_count'] += 1

        session_info = {
            'session_id': session_id,
            'bytes_sent': sessions[session_id]['bytes_sent'],
            'bytes_received': sessions[session_id]['bytes_received'],
            'total_bytes': sessions[session_id]['total_bytes'],
            'packet_count': sessions[session_id]['packet_count']
        }

        return src_port,dest_port,session_info
    # Sniff packets and call the extract_features function for each packet
    outer.append(sniff(prn=extract_features, store=0, count=10))

def stop_sniffer():
    if len(outer)>0:
        #(outer[0]).terminate()
        print("Sniffer stopped.")

atexit.register(stop_sniffer)

def log_packet(feature, action_taken):
    # Create a FirewallLog entry
    FirewallLog.objects.create(
        src_ip=feature['Src_IP'],
        dest_ip=feature['Dest_IP'],
        src_port=feature['Src_Port'],
        dest_port=feature['Dest_Port'],
        protocol=feature['protocol'],
        action=action_taken,
    )
