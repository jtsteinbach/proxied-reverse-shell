from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import threading
import random
import string
import base64
import time
import os
import subprocess

app = Flask(__name__)

# Generate key for Fernet encryption
FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)
POINT_FILE = 'point.txt'
EXPIRATION_TIME = 3600  # Expiration time in seconds (1 hour)

commands_dict = {}  # In-memory store for pending commands
results_dict = {}   # In-memory store for command results

# Generate a random 4-character alphanumeric pointer
def generate_pointer():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=4))

def ip_port_to_bytes(ip, port):
    ip_parts = [int(part) for part in ip.split('.')]
    ip_bytes = bytes(ip_parts) + port.to_bytes(2, 'big')
    return ip_bytes

# Encrypt IP and port with Fernet
def encrypt_ip_port(ip, port):
    ip_port_bytes = ip_port_to_bytes(ip, port)
    encrypted_data = cipher.encrypt(ip_port_bytes)
    base64_encoded = base64.urlsafe_b64encode(encrypted_data).decode()
    return base64_encoded[:8], base64_encoded[8:]  # First 8 chars go into connect code

def store_encrypted_ip(timestamp, pointer, decryption_key, encrypted_ip_port_remainder):
    # Store pointer and encrypted segments, without full IP/Port
    with open(POINT_FILE, 'a') as f:
        f.write(f"{timestamp} {pointer} {decryption_key.decode()} {encrypted_ip_port_remainder}\n")

def lookup_encrypted_ip(pointer):
    # Retrieve stored decryption key and remainder based on pointer
    current_time = time.time()
    with open(POINT_FILE, 'r') as f:
        lines = f.readlines()
    for line in lines:
        parts = line.strip().split()
        if len(parts) == 4:
            timestamp, stored_pointer, decryption_key, encrypted_ip_port_remainder = parts
            if stored_pointer == pointer and current_time - float(timestamp) < EXPIRATION_TIME:
                return decryption_key, encrypted_ip_port_remainder
    return None, None

def verify_and_get_ip_port(connection_code):
    # Reconstruct full encrypted IP/Port with segments
    pointer = connection_code[:4]
    encrypted_ip_prefix = connection_code[4:]
    decryption_key, encrypted_ip_remainder = lookup_encrypted_ip(pointer)
    if decryption_key is None:
        return None, None

    # Decrypt full IP/Port without logging full IP/Port or encrypted segments
    full_encrypted_ip_port = encrypted_ip_prefix + encrypted_ip_remainder
    encrypted_data = base64.urlsafe_b64decode(full_encrypted_ip_port + '==')
    cipher = Fernet(decryption_key.encode())
    decrypted_bytes = cipher.decrypt(encrypted_data)

    ip = '.'.join(map(str, decrypted_bytes[:4]))
    port = int.from_bytes(decrypted_bytes[4:], 'big')
    return ip, port

def generate_connection_code(ip, port):
    # Generate connect code from pointer and first 8 encrypted chars
    pointer = generate_pointer()
    encrypted_ip_prefix, encrypted_ip_remainder = encrypt_ip_port(ip, port)
    connection_code = pointer + encrypted_ip_prefix
    timestamp = time.time()
    store_encrypted_ip(timestamp, pointer, FERNET_KEY, encrypted_ip_remainder)
    return connection_code

def update_timestamp(pointer):
    # Update the timestamp for an active connection
    current_time = time.time()
    updated_lines = []
    with open(POINT_FILE, 'r') as f:
        lines = f.readlines()
    with open(POINT_FILE, 'w') as f:
        for line in lines:
            parts = line.strip().split()
            if len(parts) == 4 and parts[1] == pointer:
                updated_line = f"{current_time} {parts[1]} {parts[2]} {parts[3]}\n"
                updated_lines.append(updated_line)
            else:
                updated_lines.append(line)
        f.writelines(updated_lines)

@app.route('/get_code', methods=['POST'])
def get_code():
    data = request.get_json()
    port = data.get("port")
    if not port:
        return jsonify({"error": "Port is required"}), 400
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if not client_ip:
        return jsonify({"error": "Failed to obtain client IP"}), 500
    try:
        connection_code = generate_connection_code(client_ip, port)
        print(f"Generated connection code: {connection_code}")
        return jsonify({"code": connection_code})
    except Exception as e:
        return jsonify({"error": f"Failed to create connection code: {str(e)}"}), 500

@app.route('/connect', methods=['POST'])
def connect():
    data = request.get_json()
    connection_code = data.get("code")
    print(f"Received connection request with code: {connection_code}")
    if not connection_code or len(connection_code) != 12:
        return jsonify({"error": "Invalid connection code format"}), 400
    ip, port = verify_and_get_ip_port(connection_code)
    if ip is None or port is None:
        print("Pointer not found or expired.")
        return jsonify({"error": "Invalid or expired connection code"}), 400
    print(f"Decrypted IP and port: {ip}:{port}")
    return jsonify({"message": f"Connected to {ip}:{port}"})

@app.route('/send_command', methods=['POST'])
def send_command():
    data = request.get_json()
    code = data.get("code")
    command = data.get("command")
    pointer = code[:4]
    
    commands_dict[pointer] = command  # Store command for receiver to execute
    update_timestamp(pointer)
    print(f"Received command: {command}")
    return jsonify({"message": "Command relayed to receiver"})

@app.route('/fetch_command', methods=['POST'])
def fetch_command():
    data = request.get_json()
    code = data.get("code")
    pointer = code[:4]
    
    command = commands_dict.pop(pointer, None)  # Retrieve and remove command after execution
    if command is None:
        return jsonify({"command": None})
    print(f"Fetched command for pointer {pointer}: {command}")
    try:
        # Execute the command on the receiver machine
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        
        # Store result in memory
        results_dict[pointer] = output.decode("utf-8") if output else error.decode("utf-8")
    except Exception as e:
        results_dict[pointer] = f"Command execution failed: {str(e)}"
    return jsonify({"command": command})

@app.route('/fetch_result', methods=['POST'])
def fetch_result():
    data = request.get_json()
    code = data.get("code")
    pointer = code[:4]
    
    # Retrieve the result for the executed command
    result = results_dict.pop(pointer, "No response from server.")
    print(f"Fetched result for pointer {pointer}: {result}")
    return jsonify({"output": result})

def cleanup_old_keys():
    current_time = time.time()
    if os.path.exists(POINT_FILE):
        with open(POINT_FILE, 'r') as f:
            lines = f.readlines()
        with open(POINT_FILE, 'w') as f:
            for line in lines:
                parts = line.strip().split()
                if len(parts) == 4:
                    timestamp, pointer, decryption_key, encrypted_ip_port_remainder = parts
                    if current_time - float(timestamp) < EXPIRATION_TIME:
                        f.write(line)
                    else:
                        # Remove expired pointers from command and result dictionaries
                        commands_dict.pop(pointer, None)
                        results_dict.pop(pointer, None)

cleanup_thread = threading.Thread(target=lambda: (time.sleep(600), cleanup_old_keys()))
cleanup_thread.daemon = True
cleanup_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=44444)
