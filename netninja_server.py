# Net Ninja | Flask Server Software
# Created By: JT STEINBACH

from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import random
import string
import base64
import time
import redis

app = Flask(__name__)

# Initialize Redis connection
redis_client = redis.Redis(
    host='net-ninja-main-4842.redis.b.osc-fr1.scalingo-dbs.com',
    port=30757,
    username='jtstein28@gmail.com',
    password='YjCU72yX28B@@Pz',
    db=0,
    decode_responses=True
)

EXPIRATION_TIME = 1800  # Expiration in seconds (1 hour)
MAX_COMMAND_ATTEMPTS = 10  # Limit the number of attempts to fetch command results

# Generate a random 4-character pointer
def generate_pointer():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=4))

def generate_passkey():
    return Fernet.generate_key()

def ip_port_to_bytes(ip, port):
    ip_parts = [int(part) for part in ip.split('.')]
    ip_bytes = bytes(ip_parts) + port.to_bytes(2, 'big')
    return ip_bytes

def encrypt_ip_port(ip, port):
    # Generate a new passkey and cipher for each IP:PORT
    passkey = generate_passkey()
    cipher = Fernet(passkey)

    ip_port_bytes = ip_port_to_bytes(ip, port)
    encrypted_data = cipher.encrypt(ip_port_bytes)
    base64_encoded = base64.urlsafe_b64encode(encrypted_data).decode()
    
    # Return the middle section for connection code and passkey for storage
    return base64_encoded[20:28], base64_encoded[:20] + '*' + base64_encoded[28:], passkey

def store_encrypted_ip(pointer, passkey, encrypted_ip_placeholder):
    # Store encrypted IP info in Redis with expiration
    redis_client.hset(pointer, mapping={
        'passkey': passkey.decode(),
        'encrypted_ip_placeholder': encrypted_ip_placeholder
    })
    redis_client.expire(pointer, EXPIRATION_TIME)

def lookup_encrypted_ip(pointer):
    # Retrieve encrypted IP info from Redis
    data = redis_client.hgetall(pointer)
    if data:
        return data['passkey'], data['encrypted_ip_placeholder']
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

def generate_connection_code(ip, port):
    try:
        pointer = generate_pointer()
        connection_code, encrypted_ip_placeholder, passkey = encrypt_ip_port(ip, port)
        store_encrypted_ip(pointer, passkey, encrypted_ip_placeholder)
        return pointer + connection_code
    except Exception as e:
        print(f"[ERROR] generate_connection_code: {e}")  # Log the specific error
        raise

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
        return jsonify({"code": connection_code})
    except Exception as e:
        print(f"[ERROR] Failed to create connection code: {e}")  # Log the error
        return jsonify({"error": f"Failed to create connection code: {str(e)}"}), 500

@app.route('/connect', methods=['POST'])
def connect():
    data = request.get_json()
    connection_code = data.get("code")
    if not connection_code or len(connection_code) != 12:
        return jsonify({"error": "Invalid connection code format"}), 400

    ip, port = verify_and_get_ip_port(connection_code)
    if ip is None or port is None:
        return jsonify({"error": "Invalid or expired connection code"}), 400

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

    # Store command in Redis with expiration
    redis_client.setex(f"command:{pointer}", EXPIRATION_TIME, command)
    return jsonify({"message": "Command sent to receiver"})

@app.route('/fetch_command', methods=['POST'])
def fetch_command():
    data = request.get_json()
    code = data.get("code")
    pointer = code[:4]

    # Retrieve and delete the command
    command = redis_client.getdel(f"command:{pointer}")
    if command:
        return jsonify({"command": command})  # Send the command if available
    
    return '', 204  # No Content status

@app.route('/send_result', methods=['POST'])
def send_result():
    data = request.get_json()
    code = data.get("code")
    result = data.get("result")
    pointer = code[:4]

    # Store result in Redis with expiration
    redis_client.setex(f"result:{pointer}", EXPIRATION_TIME, result)
    return jsonify({"message": "Result stored for sender"})

@app.route('/fetch_result', methods=['POST'])
def fetch_result():
    data = request.get_json()
    code = data.get("code")
    pointer = code[:4]

    # Retrieve and delete the result
    result = redis_client.getdel(f"result:{pointer}")
    return jsonify({"output": result or "No response from server."})

@app.route('/end_connection', methods=['POST'])
def end_connection():
    data = request.get_json()
    code = data.get("code")
    pointer = code[:4]

    ip, _ = verify_and_get_ip_port(code)
    if request.remote_addr != ip:
        return jsonify({"error": "Unauthorized request."}), 403

    # Delete relevant keys from Redis
    redis_client.delete(pointer)
    redis_client.delete(f"command:{pointer}")
    redis_client.delete(f"result:{pointer}")
    return jsonify({"message": "Connection ended successfully."})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=44444)
