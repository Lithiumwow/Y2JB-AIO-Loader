import socket
import sys
import time

def send_payload(file_path, host, port=50000, tries=5, timeout=15):
    """Send payload file to host:port. Returns (success, error_message). error_message is None on success."""
    last_error = None
    host = (host or "").strip()
    attempt = 0
    while attempt < tries:
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            print(f"Connecting to {host}:{port}...")
            sock.connect((host, port))
            
            print(f"Sending file {file_path} ({len(data)} bytes)...")
            sock.sendall(data)
            
            sock.close()
            
            time.sleep(0.5)
            
            print('done')
            return (True, None)
            
        except ConnectionRefusedError:
            last_error = f"Connection refused ({host}:{port}). Is the remote loader running?"
            print(last_error)
        except socket.gaierror:
            last_error = f"Host not found: {host}"
            print(last_error)
        except socket.timeout:
            last_error = f"Connection timeout ({host}:{port}). Check network/firewall."
            print(last_error)
        except FileNotFoundError:
            last_error = f"File not found: {file_path}"
            print(last_error)
            return (False, last_error)
        except Exception as e:
            last_error = f"Error: {str(e)}"
            print(last_error)
        
        attempt += 1
        if attempt < tries:
            print(f"Attempt {attempt} failed, retrying...")
            time.sleep(1)
    
    print(f"Failed after {tries} attempts")
    return (False, last_error or "Failed after retries")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("""
Payload Sender - Usage:
  python SendPayload.py <host> <file> [port] [tries]

Examples:
  python SendPayload.py 192.168.1.123 lapse.js 50000
  python SendPayload.py 192.168.1.123 etahen.bin 9021

Note: Make sure the target server is listening on the specified port
""")
        sys.exit(1)

    host = sys.argv[1]
    file_path = sys.argv[2]

    if len(sys.argv) > 3:
        port = int(sys.argv[3])
    else:
        port = 50000

    print(f"Starting transmission to {host}:{port}")

    ok, err = send_payload(file_path, host, port)
    if ok:
        print("Transmission completed successfully")
        sys.exit(0)
    else:
        print("Transmission failed:", err or "")
        sys.exit(1)
