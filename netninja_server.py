from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import threading
import random
import string
import base64
import time
import subprocess

app = Flask(__name__)

# Encryption setup
FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)
EXPIRATION_TIME = 3600  # Expiration time in seconds (1 hour)

# In-memory storage
connection_data = {}  # Stores pointers, decryption keys, and encrypted IP remainders
commands_dict = {}  # Stores commands in memory
results_dict = {}  # Stores command results for sender to retrieve

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

def store_encrypted_ip(pointer, decryption_key, encrypted_ip_port_remainder):
    # Store pointer and encrypted segments in memory only
    connection_data[pointer] = {
        "decryption_key": decryption_key,
        "encrypted_ip_remainder": encrypted_ip_port_remainder,
        "timestamp": time.time()
    }

def lookup_encrypted_ip(pointer):
    # Retrieve stored decryption key and remainder based on pointer
    if pointer in connection_data:
        current_time = time.time()
        if current_time - connection_data[pointer]["timestamp"] < EXPIRATION_TIME:
            return connection_data[pointer]["decryption_key"], connection_data[pointer]["encrypted_ip_remainder"]
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
    cipher = Fernet(decryption_key)
    decrypted_bytes = cipher.decrypt(encrypted_data)

    ip = '.'.join(map(str, decrypted_bytes[:4]))
    port = int.from_bytes(decrypted_bytes[4:], 'big')
    return ip, port

def generate_connection_code(ip, port):
    # Generate connect code from pointer and first 8 encrypted chars
    pointer = generate_pointer()
    encrypted_ip_prefix, encrypted_ip_remainder = encrypt_ip_port(ip, port)
    connection_code = pointer + encrypted_ip_prefix
    store_encrypted_ip(pointer, FERNET_KEY, encrypted_ip_remainder)
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

# Send command endpoint to relay to the receiver
@app.route('/send_command', methods=['POST'])
def send_command():
    data = request.get_json()
    code = data.get("code")
    command = data.get("command")
    pointer = code[:4]
    commands_dict[pointer] = command  # Store command in memory for the pointer
    connection_data[pointer]["timestamp"] = time.time()  # Update timestamp
    print(f"Received command: {command}")
    return jsonify({"message": "Command relayed to receiver"})

@app.route('/fetch_command', methods=['POST'])
def fetch_command():
    data = request.get_json()
    code = data.get("code")
    pointer = code[:4]
    # Fetch command for this connection
    command = commands_dict.pop(pointer, None)
    return jsonify({"command": command})

@app.route('/send_result', methods=['POST'])
def send_result():
    data = request.get_json()
    code = data.get("code")
    pointer = code[:4]
    result = data.get("result")
    results_dict[pointer] = result  # Store result in memory for sender to retrieve
    return jsonify({"message": "Result stored for sender"})

@app.route('/fetch_result', methods=['POST'])
def fetch_result():
    data = request.get_json()
    code = data.get("code")
    pointer = code[:4]
    # Fetch the result for this command
    result = results_dict.pop(pointer, "No response from server.")
    return jsonify({"output": result})

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
    # Remove the connection entry with the matching pointer
    connection_data.pop(pointer, None)
    commands_dict.pop(pointer, None)
    results_dict.pop(pointer, None)
    print(f"Connection with code {code} has been ended by the original receiver.")
    return jsonify({"message": "Connection ended successfully."})

def cleanup_old_keys():
    current_time = time.time()
    for pointer in list(connection_data.keys()):
        if current_time - connection_data[pointer]["timestamp"] >= EXPIRATION_TIME:
            connection_data.pop(pointer, None)
            commands_dict.pop(pointer, None)
            results_dict.pop(pointer, None)

cleanup_thread = threading.Thread(target=lambda: (time.sleep(600), cleanup_old_keys()))
cleanup_thread.daemon = True
cleanup_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=44444)
