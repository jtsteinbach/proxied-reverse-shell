from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import threading
import random
import string
import base64
import time
import os
import secrets

app = Flask(__name__)

FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)
POINT_FILE = 'point.txt'
COMMANDS_FILE = 'commands.txt'
TOKENS_FILE = 'tokens.txt'  # Store active session tokens
EXPIRATION_TIME = 3600  # Expiration time in seconds (1 hour)

# Generate a random 4-character alphanumeric pointer
def generate_pointer():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=4))

# Generate a session token for secure command validation
def generate_token():
    return secrets.token_hex(16)

def ip_port_to_bytes(ip, port):
    ip_parts = [int(part) for part in ip.split('.')]
    ip_bytes = bytes(ip_parts) + port.to_bytes(2, 'big')
    return ip_bytes

def encrypt_ip_port(ip, port):
    ip_port_bytes = ip_port_to_bytes(ip, port)
    encrypted_data = cipher.encrypt(ip_port_bytes)
    base64_encoded = base64.urlsafe_b64encode(encrypted_data).decode()
    return base64_encoded[:8], base64_encoded[8:]

def store_encrypted_ip(timestamp, pointer, decryption_key, encrypted_ip_port_remainder, token):
    with open(POINT_FILE, 'a') as f:
        f.write(f"{timestamp} {pointer} {decryption_key.decode()} {encrypted_ip_port_remainder} {token}\n")

def lookup_encrypted_ip(pointer):
    current_time = time.time()
    with open(POINT_FILE, 'r') as f:
        lines = f.readlines()
    for line in lines:
        parts = line.strip().split()
        if len(parts) == 5:
            timestamp, stored_pointer, decryption_key, encrypted_ip_port_remainder, token = parts
            if stored_pointer == pointer and current_time - float(timestamp) < EXPIRATION_TIME:
                return decryption_key, encrypted_ip_port_remainder, token
    return None, None, None

def verify_and_get_ip_port(connection_code):
    pointer = connection_code[:4]
    encrypted_ip_prefix = connection_code[4:]
    decryption_key, encrypted_ip_remainder, _ = lookup_encrypted_ip(pointer)
    if decryption_key is None:
        return None, None
    full_encrypted_ip_port = encrypted_ip_prefix + encrypted_ip_remainder
    encrypted_data = base64.urlsafe_b64decode(full_encrypted_ip_port + '==')
    cipher = Fernet(decryption_key.encode())
    decrypted_bytes = cipher.decrypt(encrypted_data)
    ip = '.'.join(map(str, decrypted_bytes[:4]))
    port = int.from_bytes(decrypted_bytes[4:], 'big')
    return ip, port

# Function to update the timestamp in point.txt
def update_timestamp(pointer):
    current_time = time.time()
    updated_lines = []
    with open(POINT_FILE, 'r') as f:
        lines = f.readlines()
    with open(POINT_FILE, 'w') as f:
        for line in lines:
            parts = line.strip().split()
            if len(parts) == 5 and parts[1] == pointer:
                updated_line = f"{current_time} {parts[1]} {parts[2]} {parts[3]} {parts[4]}\n"
                updated_lines.append(updated_line)
            else:
                updated_lines.append(line)
        f.writelines(updated_lines)

def generate_connection_code(ip, port):
    pointer = generate_pointer()
    encrypted_ip_prefix, encrypted_ip_remainder = encrypt_ip_port(ip, port)
    connection_code = pointer + encrypted_ip_prefix
    token = generate_token()
    timestamp = time.time()
    store_encrypted_ip(timestamp, pointer, FERNET_KEY, encrypted_ip_remainder, token)
    return connection_code, token

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
        connection_code, token = generate_connection_code(client_ip, port)
        print(f"Generated connection code: {connection_code}")
        return jsonify({"code": connection_code, "token": token})
    except Exception as e:
        return jsonify({"error": f"Failed to create connection code: {str(e)}"}), 500

@app.route('/connect', methods=['POST'])
def connect():
    data = request.get_json()
    connection_code = data.get("code")
    token = data.get("token")
    print(f"Received connection request with code: {connection_code}")
    if not connection_code or len(connection_code) != 12 or not token:
        return jsonify({"error": "Invalid connection code or token format"}), 400
    ip, port = verify_and_get_ip_port(connection_code)
    if ip is None or port is None:
        print("Pointer not found or expired.")
        return jsonify({"error": "Invalid or expired connection code"}), 400
    # Store token temporarily for session
    with open(TOKENS_FILE, 'a') as f:
        f.write(f"{connection_code[:4]} {token}\n")
    print(f"Decrypted IP and port: {ip}:{port}")
    return jsonify({"message": f"Connected to {ip}:{port}"})

@app.route('/send_command', methods=['POST'])
def send_command():
    data = request.get_json()
    code = data.get("code")
    command = data.get("command")
    token = data.get("token")
    pointer = code[:4]

    # Verify session token
    if not verify_token(pointer, token):
        return jsonify({"error": "Invalid or expired session token"}), 403

    update_timestamp(pointer)
    with open(COMMANDS_FILE, 'a') as f:
        f.write(f"{pointer} {command}\n")
    return jsonify({"message": "Command sent to receiver"})

@app.route('/fetch_command', methods=['POST'])
def fetch_command():
    data = request.get_json()
    code = data.get("code")
    token = data.get("token")
    pointer = code[:4]

    # Verify session token
    if not verify_token(pointer, token):
        return jsonify({"error": "Invalid or expired session token"}), 403

    try:
        with open(COMMANDS_FILE, 'r') as f:
            lines = f.readlines()
        with open(COMMANDS_FILE, 'w') as f:
            for line in lines:
                line_pointer, command = line.strip().split(maxsplit=1)
                if line_pointer == pointer:
                    return jsonify({"command": command})
                f.write(line)
        return jsonify({"command": None})
    except Exception as e:
        return jsonify({"error": f"Failed to fetch command: {str(e)}"}), 500

@app.route('/command_output', methods=['POST'])
def command_output():
    data = request.get_json()
    code = data.get("code")
    output = data.get("output")
    token = data.get("token")
    pointer = code[:4]

    # Verify session token
    if not verify_token(pointer, token):
        return jsonify({"error": "Invalid or expired session token"}), 403

    with open(f"{pointer}_output.txt", 'w') as f:
        f.write(output)
    return jsonify({"message": "Output received"})

# Helper function to verify tokens
def verify_token(pointer, token):
    with open(TOKENS_FILE, 'r') as f:
        lines = f.readlines()
    for line in lines:
        stored_pointer, stored_token = line.strip().split()
        if stored_pointer == pointer and stored_token == token:
            return True
    return False

def cleanup_old_keys():
    current_time = time.time()
    if os.path.exists(POINT_FILE):
        with open(POINT_FILE, 'r') as f:
            lines = f.readlines()
        with open(POINT_FILE, 'w') as f:
            for line in lines:
                parts = line.strip().split()
                if len(parts) == 5:
                    timestamp, pointer, decryption_key, encrypted_ip_port_remainder, token = parts
                    if current_time - float(timestamp) < EXPIRATION_TIME:
                        f.write(line)

cleanup_thread = threading.Thread(target=lambda: (time.sleep(600), cleanup_old_keys()))
cleanup_thread.daemon = True
cleanup_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=44444, ssl_context=('cert.pem', 'key.pem'))
