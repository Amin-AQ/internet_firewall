from scapy.all import sniff, IP, TCP

# Function to process a packet and extract features
def extract_features(packet):
    features = {}

    # Extract Ethernet layer information
    if packet.haslayer('Ethernet'):
        features['Src_MAC'] = packet['Ethernet'].src
        features['Dst_MAC'] = packet['Ethernet'].dst

    # Extract IP layer information
    if packet.haslayer('IP'):
        features['Src_IP'] = packet['IP'].src
        features['Dst_IP'] = packet['IP'].dst

    # Extract TCP layer information
    if packet.haslayer('TCP'):
        features['Src_Port'] = packet['TCP'].sport
        features['Dst_Port'] = packet['TCP'].dport
        features['Flags'] = packet['TCP'].flags

        # Calculate bytes sent and bytes received based on payload size
        if packet.haslayer('Raw'):
            features['Bytes_Sent'] = len(packet['Raw'].load) if packet['IP'].src == features['Src_IP'] else 0
            features['Bytes_Received'] = len(packet['Raw'].load) if packet['IP'].src == features['Dst_IP'] else 0

        # Print extracted features of tcp packet
        if features['Src_Port'] == 80 or features['Dst_Port'] == 80 or features['Src_Port'] == 443 or features['Dst_Port'] == 443:
            print("Extracted Features:", features)


# Sniff packets and call the extract_features function for each packet
sniff(prn=extract_features, store=0, count=10)  # Adjust count as needed
