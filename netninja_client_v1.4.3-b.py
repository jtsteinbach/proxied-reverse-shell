#!/usr/bin/env python3
# Net Ninja | Client Software
# Created By: JT STEINBACH

version = "v1.4.3-b"

import os
import sys
import time
import threading
import subprocess
import warnings
warnings.showwarning = lambda *args, **kwargs: None

try:
    import requests
except ImportError:
    subprocess.run(["pip3", "install", "requests"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    import requests

SERVER_URL = "https://connect-host.netninja.sh"
session = requests.Session()
session.verify = True
stop_threads = False

version_url = "https://program-data.netninja.sh/current-version"
response = requests.get(version_url, timeout=5)
response.raise_for_status()
online_version = response.text.strip()

LIGHT_YELLOW = "\033[93m"
BOLD = "\033[1m"
TILT = "\033[3m"
RESET = "\033[0m"

def intro():
    print(f"""
  {BOLD}{TILT}NET NINJA{RESET}    {version}
  {LIGHT_YELLOW}https://netninja.sh/{RESET}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
""")
    
def cmd_usage():
    print(f"""⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡀⠀
⠀⠈⠙⢿⣿⣿⣿⣿⣿⣧⡀⠀⠀⣠⣿⣿⣄⠀⠀⢀⣼⣿⣿⣿⣿⣿⡿⠋⠁⠀
⠀⠀⠀⠀⠈⠛⢿⣿⣿⣿⣿⣿⣿⡿⠛⠛⢿⣿⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠘⣿⣷⣀⣀⣾⣿⠃⠀⠀⠈⠉⠀⠀⠀⠀⠀        {BOLD}{TILT}NET NINJA{RESET}    {version}
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⠿⠿⣿⣿⡄⠀⠀⠀⠀⠀⠀           {LIGHT_YELLOW}https://netninja.sh/{RESET}
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⡟⠀⠀⠀⠀⢻⣿⣷⣾⡀
⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⡷⠀⠀⠀⠀⢾⣿⣿⣿⣧⠀⠀    {BOLD}"the worlds most secure reverse proxy"{RESET}
⠀⠀⠀⠀⠀⠀⠀⢰⣿⡿⠟⠁⠀⠀⠀⠀⠀⠀⠈⠻⢿⣿⡆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⡄⠀
⠀⠀
    {BOLD}USAGE:    ninja [argument]{RESET}
    {BOLD}ARGUMENTS:{RESET}
    
      -o  <port>  (-s, silent optional)                 'Start as receiver and generate code'
      -c  <connection_code>                             'Connect as sender'

      -op <persistent_code>  (-s, silent optional)      'Open persistent connection'   (WIP)
      -cp <persistent_code>                             'Connect as persistent sender' (WIP)

      -update                                           'Update client version'
        
    Need more help? {LIGHT_YELLOW}https://netninja.sh/wiki{RESET}
        """)

def get_connection_code(port):
    try:
        response = session.post(f"{SERVER_URL}/get_code", json={"port": port}, timeout=5)
        response.raise_for_status()
        connection_code = response.json().get("code")
        if connection_code:
            print(f"Connection code: {BOLD}{TILT}{connection_code}{RESET}\n")
            return connection_code
        else:
            print("Failed to retrieve a valid connection code.\n")
    except requests.RequestException:
        sys.exit(1)

def connect_with_code(connection_code):
    try:
        response = session.post(f"{SERVER_URL}/connect", json={"code": connection_code}, timeout=5)
        response.raise_for_status()
        response_json = response.json()
        
        if response_json.get("message"):
            print(f"Session opened: {TILT}SENDER{RESET}\n{BOLD}Enter command (or 'exit'){RESET}\n")
            while True:
                command = input("  >>  ")
                if command.lower() == 'exit':
                    break
                send_command(connection_code, command)
        else:
            print("Failed to establish connection. Server response:", response_json)
    except requests.RequestException as e:
        sys.exit(1)

def send_command(connection_code, command):
    try:
        response = session.post(f"{SERVER_URL}/send_command", json={"code": connection_code, "command": command}, timeout=5)
        response.raise_for_status()
        fetch_command_output(connection_code)
    except requests.RequestException:
        pass

def fetch_command_output(connection_code):
    for attempt in range(10):
        time.sleep(1 * (attempt + 1))  # Exponential backoff: 1s, 2s, ..., 10s
        try:
            response = session.post(f"{SERVER_URL}/fetch_result", json={"code": connection_code}, timeout=5)
            response.raise_for_status()
            output = response.json().get("output", "No response from server.")
            if output != "No response from server.":
                print("\n"+output)
                return
        except requests.RequestException:
            pass

def send_result(connection_code, result):
    try:
        response = session.post(f"{SERVER_URL}/send_result", json={"code": connection_code, "result": result}, timeout=5)
        response.raise_for_status()
    except requests.RequestException:
        pass

def fetch_and_execute(connection_code):
    global stop_threads
    consecutive_failures = 0
    max_failures = 5

    while not stop_threads:
        try:
            response = session.post(f"{SERVER_URL}/fetch_command", json={"code": connection_code}, timeout=30)
            if response.status_code == 204:
                consecutive_failures += 1
                if consecutive_failures >= max_failures:
                    break
                continue
            elif response.status_code == 200:
                command = response.json().get("command")
                if command:
                    print(f"  >>  {command}")
                    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    output, error = process.communicate()
                    result = output.decode(errors="ignore") if output else error.decode(errors="ignore")
                    send_result(connection_code, result)
                    consecutive_failures = 0
            else:
                consecutive_failures += 1

        except requests.RequestException as e:
            consecutive_failures += 1
            if consecutive_failures >= max_failures:
                break
            time.sleep(2)

        except ValueError:
            consecutive_failures += 1
            if consecutive_failures >= max_failures:
                break
            time.sleep(2)

    if stop_threads:
        pass

def core():
    global stop_threads
    if len(sys.argv) < 2:
        cmd_usage()
        sys.exit()
    if "-s" not in sys.argv:
        intro()
        if online_version != version:
            print(f"{LIGHT_YELLOW}[UPDATE]{RESET} New version available! {online_version} '{BOLD}ninja -update{RESET}'")

    action = sys.argv[1]
    if action == "-o":
        try:
            port = int(sys.argv[2])
            connection_code = get_connection_code(port)
            if "-s" in sys.argv:
                sys.stdout = open(os.devnull, 'w')
                sys.stderr = open(os.devnull, 'w')
            print(f"Session opened: {TILT}RECEIVER{RESET}\n{BOLD}[Press ENTER to terminate]{RESET}")
            command_listener = threading.Thread(target=fetch_and_execute, args=(connection_code,))
            command_listener.start()
            while True:
                if input("").lower() != "404":
                    stop_threads = True
                    return sys.exit()
        except ValueError:
            print("Invalid port number.")
    elif action == "-c":
        connection_code = sys.argv[2]
        connect_with_code(connection_code)
    elif action == "-update":
        subprocess.run(["curl", "-s", "-L", "install.netninja.sh", "|", "python3"], shell=True)
    else:
        cmd_usage()

try:
    core()
except KeyboardInterrupt:
    stop_threads = True
    sys.exit()
except Exception as e:
    input("Press ENTER to continue...")
