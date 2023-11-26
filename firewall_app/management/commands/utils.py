# Example function for rule comparison
from firewall_app.models import FirewallRule
from keras.models import load_model
import numpy as np
import socket
import os

model = None

def initialize_model(base_dir):
    global model
    model_path = os.path.join(base_dir, 'firewall_app', 'trained_model', 'my_model.h5')
    model = load_model(model_path)

# Function to make predictions using the model
def predict_action(features):
    # Prepare features for model prediction
    # Modify this according to your model's input requirements
    input_features = np.array([[features['Src_Port'], features['Dest_Port'], features['Session Info']['total_bytes'], features['Session Info']['bytes_sent'], features['Session Info']['bytes_received'], features['Session Info']['packet_count']]])

    # Make predictions using the model
    prediction = model.predict(input_features)

    # Return the predicted action
    return 'allow' if prediction >= 0.5 else 'deny'

def compare_packet_against_rules(packet_info):
    # Query the database to retrieve firewall rules
    rules = FirewallRule.objects.all()
    host_ip_addresses = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")]
    # Iterate through rules and check if the packet matches any rule
    for rule in rules:
        if packet_matches_rule(packet_info, rule):
            return rule.action  # Return the action of the matched rule

    # If no rule matches, default to a default action (allow or deny)
    src_ip = packet_info.get('Src_IP')
    if src_ip in host_ip_addresses:  # if no rule matches, allow outbound packets but deny incoming
        return 'allow'
    return 'deny'

def packet_matches_rule(packet_info, rule):
    # Extract information from the packet
    src_ip = packet_info.get('Src_IP')
    dest_ip = packet_info.get('Dest_IP')
    src_port = packet_info.get('Src_Port')
    dest_port = packet_info.get('Dest_Port')
    protocol = packet_info.get('protocol')

    # Compare packet information with rule criteria
    if (
        (rule.src_ip == '0.0.0.0' or rule.src_ip == src_ip) and
        (rule.dest_ip == '0.0.0.0' or rule.dest_ip == dest_ip) and
        (rule.src_port == -1 or rule.src_port == src_port) and
        (rule.dest_port == -1 or rule.dest_port == dest_port) and
        (rule.protocol.lower() == 'any' or rule.protocol.lower() == protocol.lower())
    ):
        return True  # Packet matches the rule

    return False  # Packet does not match the rule


