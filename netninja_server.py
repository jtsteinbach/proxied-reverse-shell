from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import random
import string
import base64
import time
import subprocess
import os

app = Flask(__name__)

FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)
POINT_FILE = 'point.txt'
EXPIRATION_TIME = 3600  # Expiration time for point.txt entries in seconds

commands_output = {}  # Dictionary to store command outputs by connection code

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
    return base64_encoded[:8], base64_encoded[8:]

def store_encrypted_ip(timestamp, pointer, decryption_key, encrypted_ip_port_remainder):
    with open(POINT_FILE, 'a') as f:
        f.write(f"{timestamp} {pointer} {decryption_key.decode()} {encrypted_ip_port_remainder}\n")

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

def verify_and_get_ip_port(connection_code):
    pointer = connection_code[:4]
    encrypted_ip_prefix = connection_code[4:]
    decryption_key, encrypted_ip_remainder = lookup_encrypted_ip(pointer)
    if decryption_key is None:
        return None, None

    full_encrypted_ip_port = encrypted_ip_prefix + encrypted_ip_remainder
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

    if not code or not command:
        return jsonify({"error": "Connection code and command are required"}), 400

    ip, port = verify_and_get_ip_port(code)
    if ip is None:
        return jsonify({"error": "Invalid or expired connection code"}), 400

    print(f"Received command: {command} for code: {code}")
    pointer = code[:4]

    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        if error:
            commands_output[code] = error.decode("utf-8")
        else:
            commands_output[code] = output.decode("utf-8")

        update_timestamp(pointer)
        return jsonify({"message": "Command sent successfully"})
    except Exception as e:
        print(f"Command execution failed: {str(e)}")
        return jsonify({"error": f"Command execution failed: {str(e)}"}), 500

@app.route('/fetch_result', methods=['POST'])
def fetch_result():
    data = request.get_json()
    code = data.get("code")

    output = commands_output.pop(code, "No response from server.")
    return jsonify({"output": output})

@app.route('/end_connection', methods=['POST'])
def end_connection():
    data = request.get_json()
    code = data.get("code")

    if not code or len(code) != 12:
        return jsonify({"error": "Invalid connection code format"}), 400

    ip, _ = verify_and_get_ip_port(code)
    current_ip = request.remote_addr
    if ip != current_ip:
        return jsonify({"error": "Unauthorized request. Only the original receiver can end the connection."}), 403

    pointer = code[:4]

    try:
        with open(POINT_FILE, 'r') as f:
            lines = f.readlines()
        with open(POINT_FILE, 'w') as f:
            for line in lines:
                parts = line.strip().split()
                if len(parts) > 1 and parts[1] != pointer:
                    f.write(line)

        commands_output.pop(code, None)  # Remove any remaining output associated with this code
        print(f"Connection with code {code} has been ended by the original receiver.")
        return jsonify({"message": "Connection ended successfully."})
    except Exception as e:
        print(f"Error during file update: {str(e)}")
        return jsonify({"error": "Failed to end connection due to server error"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=44444)
