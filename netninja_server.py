# Net Ninja | Flask Server Software
# Created By: JT STEINBACH

from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import threading
import random
import string
import base64
import time
import os

app = Flask(__name__)

# Generate a secure key for encryption
FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)
POINT_FILE = 'point.txt'
EXPIRATION_TIME = 3600  # Expiration in seconds (1 hour)
MAX_COMMAND_ATTEMPTS = 10  # Limit the number of attempts to fetch command results

# Store in-memory command and result dictionaries
commands_dict = {}  # { pointer: command }
results_dict = {}   # { pointer: result }

# Generate a random 4-character pointer
def generate_pointer():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=4))

def ip_port_to_bytes(ip, port):
    ip_parts = [int(part) for part in ip.split('.')]
    ip_bytes = bytes(ip_parts) + port.to_bytes(2, 'big')
    return ip_bytes

def encrypt_ip_port(ip, port):
    ip_port_bytes = ip_port_to_bytes(ip, port)
    encrypted_data = cipher.encrypt(ip_port_bytes)
    base64_encoded = base64.urlsafe_b64encode(encrypted_data).decode()
    return base64_encoded[20:28], base64_encoded[:20] + '*' + base64_encoded[28:]

def store_encrypted_ip(timestamp, pointer, decryption_key, encrypted_ip_placeholder):
    with open(POINT_FILE, 'a') as f:
        f.write(f"{timestamp} {pointer} {decryption_key.decode()} {encrypted_ip_placeholder}\n")
    #print(f"Stored pointer {pointer} in point.txt")

def lookup_encrypted_ip(pointer):
    current_time = time.time()
    with open(POINT_FILE, 'r') as f:
        lines = f.readlines()
    for line in lines:
        parts = line.strip().split()
        if len(parts) == 4:
            timestamp, stored_pointer, decryption_key, encrypted_ip_placeholder = parts
            if stored_pointer == pointer and current_time - float(timestamp) < EXPIRATION_TIME:
                return decryption_key, encrypted_ip_placeholder
    return None, None

def verify_and_get_ip_port(connection_code):
    pointer = connection_code[:4]
    encrypted_code_section = connection_code[4:]
    decryption_key, encrypted_ip_placeholder = lookup_encrypted_ip(pointer)
    if not decryption_key:
        return None, None

    full_encrypted_ip_port = encrypted_ip_placeholder.replace('*', encrypted_code_section)
    encrypted_data = base64.urlsafe_b64decode(full_encrypted_ip_port + '==')
    cipher = Fernet(decryption_key.encode())
    decrypted_bytes = cipher.decrypt(encrypted_data)

    ip = '.'.join(map(str, decrypted_bytes[:4]))
    port = int.from_bytes(decrypted_bytes[4:], 'big')
    return ip, port

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

def generate_connection_code(ip, port):
    pointer = generate_pointer()
    connection_code, encrypted_ip_placeholder = encrypt_ip_port(ip, port)
    timestamp = time.time()
    store_encrypted_ip(timestamp, pointer, FERNET_KEY, encrypted_ip_placeholder)
    return pointer + connection_code

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
        #print(f"Generated connection code: {connection_code}")
        return jsonify({"code": connection_code})
    except Exception as e:
        return jsonify({"error": f"Failed to create connection code: {str(e)}"}), 500

@app.route('/connect', methods=['POST'])
def connect():
    data = request.get_json()
    connection_code = data.get("code")
    #print(f"Received connection request with code: {connection_code}")
    if not connection_code or len(connection_code) != 12:
        return jsonify({"error": "Invalid connection code format"}), 400

    ip, port = verify_and_get_ip_port(connection_code)
    if ip is None or port is None:
        #print("Pointer not found or expired.")
        return jsonify({"error": "Invalid or expired connection code"}), 400

    #print(f"Decrypted IP and port: {ip}:{port}")
    return jsonify({"message": f"Connected to {ip}:{port}"})

@app.route('/send_command', methods=['POST'])
def send_command():
    data = request.get_json()
    code = data.get("code")
    command = data.get("command")
    pointer = code[:4]

    if not code or not command:
        return jsonify({"error": "Connection code and command are required"}), 400

    ip, port = verify_and_get_ip_port(code)
    if ip is None:
        return jsonify({"error": "Invalid or expired connection code"}), 400

    commands_dict[pointer] = command
    update_timestamp(pointer)
    #print(f"Received command: {command} for pointer: {pointer}")
    return jsonify({"message": "Command sent to receiver"})

@app.route('/fetch_command', methods=['POST'])
def fetch_command():
    data = request.get_json()
    code = data.get("code")
    pointer = code[:4]

    command = commands_dict.pop(pointer, None)
    if not command:
        return jsonify({"error": "No command found"}), 404
    return jsonify({"command": command})

@app.route('/send_result', methods=['POST'])
def send_result():
    data = request.get_json()
    code = data.get("code")
    result = data.get("result")
    pointer = code[:4]

    results_dict[pointer] = result
    return jsonify({"message": "Result stored for sender"})

@app.route('/fetch_result', methods=['POST'])
def fetch_result():
    data = request.get_json()
    code = data.get("code")
    pointer = code[:4]

    result = results_dict.pop(pointer, "No response from server.")
    return jsonify({"output": result})

@app.route('/end_connection', methods=['POST'])
def end_connection():
    data = request.get_json()
    code = data.get("code")
    pointer = code[:4]

    ip, _ = verify_and_get_ip_port(code)
    if request.remote_addr != ip:
        return jsonify({"error": "Unauthorized request."}), 403

    with open(POINT_FILE, 'r') as f:
        lines = f.readlines()
    with open(POINT_FILE, 'w') as f:
        for line in lines:
            parts = line.strip().split()
            if len(parts) > 1 and parts[1] != pointer:
                f.write(line)
    commands_dict.pop(pointer, None)
    results_dict.pop(pointer, None)
    #print(f"Connection with code {code} has been ended.")
    return jsonify({"message": "Connection ended successfully."})

def cleanup_old_keys():
    current_time = time.time()
    if os.path.exists(POINT_FILE):
        with open(POINT_FILE, 'r') as f:
            lines = f.readlines()
        with open(POINT_FILE, 'w') as f:
            for line in lines:
                parts = line.strip().split()
                if len(parts) == 4:
                    timestamp, pointer, decryption_key, encrypted_ip_placeholder = parts
                    if current_time - float(timestamp) < EXPIRATION_TIME:
                        f.write(line)

cleanup_thread = threading.Thread(target=lambda: (time.sleep(600), cleanup_old_keys()))
cleanup_thread.daemon = True
cleanup_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=44444)
