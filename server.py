import fnmatch
import json
import logging
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename as werkzeug_secure_filename
import os

# Configure logging to ensure output goes to console
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout,
    force=True
)
logger = logging.getLogger(__name__)
from src.SendPayload import send_payload
from src.delete_payload import handle_delete_payload
from src.download_payload import handle_url_download
from src.repo_manager import update_payloads, add_repo_entry, delete_repo_entry
from src.ps5_utils import auto_replace_download0, patch_blocker
import time
import threading
import requests
import socket
from src.ftp_manager import list_ftp_directory, delete_item, create_directory, rename_item, download_file_content, upload_file_content
import io
from flask import send_file
import uuid
from src.dns_server import DNSServer
from src.backpork.core import BackporkEngine
from src.backpork_manager import (
    list_installed_games, create_fakelib_folder, fetch_system_library,
    process_library_for_game, REQUIRED_LIBS
)
from src.features import setup_logging, run_startup_tasks, get_logs
from src.system_manager import get_system_stats, power_control
import subprocess

app = Flask(__name__)
app.secret_key = 'Nazky'
CORS(app)

dns_service = None
_download0_auto_check_done = False

PAYLOAD_DIR = "payloads"
ELF_DIR = "payloads/elf"
DAT_DIR = "payloads/dat"
CONFIG_DIR = "static/config"
CONFIG_FILE = os.path.join(CONFIG_DIR, "settings.json")
PAYLOAD_CONFIG_FILE = os.path.join(CONFIG_DIR, "payload_config.json")
PAYLOAD_ORDER_FILE = os.path.join(CONFIG_DIR, "payload_order.json")
PAYLOAD_DELAYS_FILE = os.path.join(CONFIG_DIR, "payload_delays.json")
PAYLOAD_DELAY_FLAGS_FILE = os.path.join(CONFIG_DIR, "payload_delay_flags.json")
DNS_CONFIG_FILE = os.path.join(CONFIG_DIR, "dns_rules.json")
ALLOWED_EXTENSIONS = {'bin', 'elf', 'js', 'dat'}
url = "http://localhost:8000/send_payload"

os.makedirs(PAYLOAD_DIR, exist_ok=True)
os.makedirs(ELF_DIR, exist_ok=True)
os.makedirs(DAT_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs('templates', exist_ok=True)

if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, 'w') as f:
        json.dump({"ajb": "false", "ip": ""}, f)

def get_payload_config():
    if not os.path.exists(PAYLOAD_CONFIG_FILE):
        return {}
    try:
        with open(PAYLOAD_CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def get_payload_order():
    if not os.path.exists(PAYLOAD_ORDER_FILE):
        return []
    try:
        with open(PAYLOAD_ORDER_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

def save_payload_order(order):
    with open(PAYLOAD_ORDER_FILE, 'w') as f:
        json.dump(order, f, indent=4)

def get_payload_delays():
    if not os.path.exists(PAYLOAD_DELAYS_FILE):
        return {}
    try:
        with open(PAYLOAD_DELAYS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_payload_delays(data):
    with open(PAYLOAD_DELAYS_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def save_payload_config(config):
    with open(PAYLOAD_CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def get_config():
    if not os.path.exists(CONFIG_FILE):
        return {"ajb": "false", "ip": ""}
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return {"ajb": "false", "ip": ""}

def update_config(key, value):
    config = get_config()
    config[key] = str(value)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def get_dns_rules():
    if not os.path.exists(DNS_CONFIG_FILE):
        return []
    try:
        with open(DNS_CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

def save_dns_rules(rules):
    with open(DNS_CONFIG_FILE, 'w') as f:
        json.dump(rules, f, indent=4)
    if dns_service:
        dns_service.load_rules()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def secure_filename(filename):
    import re
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)

# suka nxj nezinau ka cia blet daryt kurwa.
def is_port_open(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except:
        return False

def check_ajb():
    # tikrinam ar nxj state ijungtas ar ne
    last_port_state = False
    
    while True:
        try:
            config = get_config()
            # ajb ijungtas = pisam
            if config.get("ajb", "false").lower() == "true":
                ip_address = config.get("ip", "").strip()

                if ip_address:
                    # duris atidarytos = pisam payloada
                    try:
                        _loader_port = int(get_config().get("loader_port", "50000"))
                    except (ValueError, TypeError):
                        _loader_port = 50000
                    current_port_state = is_port_open(ip_address, _loader_port)
                    
                    #bbd aiskint. pashol nxj debilai
                    if current_port_state and not last_port_state:
                        print(f"[AJB] Target {ip_address}:{_loader_port} detected OPEN. Initiating sequence...")
                        
                        try:
                            response = requests.post(url, json={
                                "IP": ip_address,
                                "payload": ""
                            })
                            if response.status_code == 200:
                                print("[AJB] Sequence completed successfully.")
                            else:
                                print(f"[AJB] Error: {response.text}")
                        except Exception as req_e:
                             print(f"[AJB] Connection Error during trigger: {req_e}")

                    # tikrinam ar resetino tsage
                    # duris uzsidaro (ps issijungia or tt) , resetinam state
                    # kai ps injugs turetu veikt
                    elif not current_port_state and last_port_state:
                         print(f"[AJB] Target {ip_address}:{_loader_port} closed. Resetting automation state.")
                    
                    # surasau paskutine duru state, kad zinot kada keistis
                    last_port_state = current_port_state
                else:
                    print("[AJB] Enabled but IP missing")
            else:
                last_port_state = False

        except Exception as e:
            print("[AJB] Error:", str(e))

        finally:
            time.sleep(5)

def _run_download0_auto_update():
    global _download0_auto_check_done
    if _download0_auto_check_done:
        return
    _download0_auto_check_done = True
    try:
        print("[REPO] Auto-checking download0.dat for update (first load)...")
        update_payloads(targets=['download0.dat'])
    except Exception as e:
        print(f"[REPO] Auto-update download0.dat failed: {e}")


@app.route("/")
def home():
    global _download0_auto_check_done
    if not _download0_auto_check_done:
        threading.Thread(target=_run_download0_auto_update, daemon=True).start()
    config = get_config()
    ps5_ip = (config.get('ip') or '').strip()
    voidshell_port = config.get('voidshell_port') or '7007'
    try:
        int(voidshell_port)
    except (ValueError, TypeError):
        voidshell_port = '7007'
    return render_template('index.html', ps5_ip=ps5_ip, voidshell_port=voidshell_port)

@app.route('/api/payload_config', methods=['GET'])
def get_payload_config_route():
    return jsonify(get_payload_config())

@app.route('/api/payload_config/toggle', methods=['POST'])
def toggle_payload_config():
    try:
        data = request.json
        filename = data.get('filename')
        enabled = data.get('enabled')
        
        if not filename:
            return jsonify({"error": "Missing filename"}), 400
            
        config = get_payload_config()
        config[filename] = enabled
        save_payload_config(config)
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/payload_order', methods=['GET', 'POST'])
def handle_payload_order():
    if request.method == 'GET':
        return jsonify(get_payload_order())
    
    if request.method == 'POST':
        try:
            order = request.json.get('order', [])
            save_payload_order(order)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/api/payload_delay', methods=['GET', 'POST'])
def handle_payload_delay():
    if request.method == 'GET':
        return jsonify(get_payload_delays())
    
    if request.method == 'POST':
        try:
            data = request.json
            filename = data.get('filename')
            delay = data.get('delay')
            
            if not filename:
                return jsonify({"error": "Missing filename"}), 400
            
            delays = get_payload_delays()
            if delay is None or delay == "":
                if filename in delays:
                    del delays[filename]
            else:
                delays[filename] = int(delay)
                
            save_payload_delays(delays)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

def get_payload_delay_flags():
    if not os.path.exists(PAYLOAD_DELAY_FLAGS_FILE):
        return {}
    try:
        with open(PAYLOAD_DELAY_FLAGS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_payload_delay_flags(flags):
    with open(PAYLOAD_DELAY_FLAGS_FILE, 'w') as f:
        json.dump(flags, f, indent=4)

@app.route('/api/payload_delays', methods=['GET'])
def get_payload_delays_route():
    return jsonify(get_payload_delay_flags())

@app.route('/api/payload_delays/toggle', methods=['POST'])
def toggle_payload_delay_flag():
    try:
        data = request.json
        filename = data.get('filename')
        enabled = data.get('enabled')
        
        if not filename:
            return jsonify({"error": "Missing filename"}), 400
            
        flags = get_payload_delay_flags()
        flags[filename] = enabled
        save_payload_delay_flags(flags)
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/edit_ajb', methods=['POST'])
def edit_ajb():
    new_content = request.json.get('content')
    update_config("ajb", new_content)
    return "Settings updated!"

@app.route('/edit_ip', methods=['POST'])
def edit_ip():
    new_content = request.json.get('content')
    update_config("ip", new_content)
    return "Settings updated!"

@app.route('/list_payloads')
def list_files():
    folder = "payloads"
    payload_files = []
    try:
        for root, dirs, files in os.walk(folder):
            for file in files:
                if file.lower().endswith(('.bin', '.elf', '.js', '.dat')):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, folder)
                    rel_path = rel_path.replace("\\", "/") 
                    payload_files.append(rel_path)
        
        order = get_payload_order()
        weights = {name: i for i, name in enumerate(order)}
        payload_files.sort(key=lambda x: weights.get(x, 9999))
        
        return jsonify(payload_files)
    except Exception as e:
        return jsonify({"error": "Folder not found"}), 404

@app.route('/upload_payload', methods=['POST'])
def upload_payload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        
        if filename.lower().endswith('.elf'):
            save_path = os.path.join(ELF_DIR, filename)
        else:
            save_path = os.path.join(PAYLOAD_DIR, filename)

        try:
            file.save(save_path)
            print(f"[UPLOAD] Saved {filename}")
            return jsonify({
                'success': True,
                'filename': filename,
                'path': save_path
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/download_payload_url', methods=['POST'])
def download_payload_url():
    try:
        data = request.get_json()
        url = data.get('url')
        print(f"[DOWNLOAD] Fetching from {url}...")
        response, status_code = handle_url_download(url, PAYLOAD_DIR, ALLOWED_EXTENSIONS)
        
        if status_code == 200:
            filename = response.get('filename')
            if filename:
                entry = {
                    "type": "direct",
                    "url": url,
                    "save_path": f"payloads/{filename}"
                }
                add_repo_entry(filename, entry)
        
        return jsonify(response), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/send_payload", methods=["POST"])
def sending_payload():
    try:
        data = request.get_json()
        host = (data.get("IP") or "").strip()
        payload = data.get("payload")

        if not host:
            return jsonify({"error": "Missing IP parameter"}), 400
        global_config = get_config()
        try:
            loader_port = int(global_config.get("loader_port", "50000"))
        except (ValueError, TypeError):
            loader_port = 50000
        if not payload:
            print("--- Starting Auto-Jailbreak Sequence ---")
            
            config = get_payload_config()

            print(f"[SEND] lapse.js -> {host}:{loader_port}")
            result, send_err = send_payload(file_path='payloads/js/lapse.js', host=host, port=loader_port)
            time.sleep(10)
            
            if result:
                global_config = get_config()
                kstuff_enabled = global_config.get("kstuff", "true") == "true"
                kstuff_result = True 

                if kstuff_enabled:
                    kstuff_path = os.path.join(ELF_DIR, 'kstuff.elf')
                    if not os.path.exists(kstuff_path):
                        kstuff_path = 'payloads/kstuff.elf'

                    print(f"[SEND] kstuff.elf -> {host}:9021")
                    kstuff_result, kstuff_err = send_payload(file_path=kstuff_path, host=host, port=9021)
                    time.sleep(10)
                else:
                    kstuff_result, kstuff_err = True, None
                    print("[SKIP] kstuff.elf (Disabled in Settings)")
                
                if kstuff_result:
                    files = []
                    for root, _, filenames in os.walk(PAYLOAD_DIR):
                        for f in filenames:
                            rel_path = os.path.relpath(os.path.join(root, f), PAYLOAD_DIR).replace("\\", "/")
                            files.append(rel_path)

                    try:
                        order = get_payload_order()
                        weights = {name: i for i, name in enumerate(order)}
                        files.sort(key=lambda x: weights.get(x, 9999))
                    except Exception as e:
                        print(f"[SORT] Error sorting payloads: {e}")

                    active_payloads = []
                    for f in files:
                        if (config.get(f, True) and config.get(os.path.basename(f), True)):
                             active_payloads.append(f)
                    
                    print(f"--- Active Payloads in Queue: {len(active_payloads)} ---")
                    for p in active_payloads:
                        print(f"  • {p}")
                    print("-----------------------------------")

                    delay_flags = get_payload_delay_flags()
                    global_config = get_config()
                    try:
                        delay_time = float(global_config.get("global_delay", "5"))
                    except:
                        delay_time = 5.0

                    for filename in files:
                        if not config.get(filename, True) or not config.get(os.path.basename(filename), True):
                            continue

                        if (fnmatch.fnmatch(filename, '*.bin') or fnmatch.fnmatch(filename, '*.elf')) and 'kstuff.elf' not in filename:
                            print(f"[SEND] {filename} -> {host}:9021")
                            result, send_err = send_payload(file_path=os.path.join(PAYLOAD_DIR,filename), host=host, port=9021)
                            
                            if delay_flags.get(filename, False):
                                print(f"[WAIT] Sleeping {delay_time}s for {filename}...")
                                time.sleep(delay_time)
                            else:
                                time.sleep(0.5)
                            
                            if not result:
                                print(f"[FAIL] Could not send {filename}")
                                return jsonify({"error": send_err or f"Failed to send {filename}"}), 500
                    
                    print("--- Auto-Jailbreak Sequence Complete ---")
                    return jsonify({"success": True, "message": "All payloads sent successfully"})
                else:
                    return jsonify({"error": kstuff_err or "Failed to send kstuff.elf"}), 500
            else:
                return jsonify({"error": send_err or "Failed to send lapse.js"}), 500
        else:
            port = 9021
            if payload.lower().endswith('.js'):
                port = loader_port
            
            print(f"[MANUAL] Sending {payload} -> {host}:{port}")
            result, send_err = send_payload(file_path=payload, host=host, port=port)
            
            if result:
                return jsonify({"success": True, "message": "Custom payload sent"})
            else:
                return jsonify({"error": send_err or "Failed to send custom payload"}), 500

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return jsonify({"error": str(e)}), 500
    
@app.route('/delete_payload', methods=['POST'])
def delete_payload():
    try:
        data = request.get_json()
        print(f"[DELETE] Request: {data}")
        response, status_code = handle_delete_payload(data, PAYLOAD_DIR, ALLOWED_EXTENSIONS)
        return jsonify(response), status_code

    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'Failed to delete file'
        }), 500

@app.route('/list_repos')
def list_repos():
    try:
        repo_file = os.path.join("static", "config", "repos.json")
        with open(repo_file, 'r') as f:
            repos = json.load(f)
        return jsonify(list(repos.keys()))
    except:
        return jsonify([])

@app.route('/update_repos', methods=['POST'])
def update_repos():
    try:
        data = request.get_json() or {}
        targets = data.get('targets', ['all'])
        print(f"[REPO] Updating targets: {targets}")
        result = update_payloads(targets)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/settings/repos')
def repo_manager_ui():
    return render_template('repos.html')

@app.route('/api/repos/list')
def get_repo_list():
    try:
        with open(os.path.join("static", "config", "repos.json"), 'r') as f:
            return jsonify(json.load(f))
    except:
        return jsonify({})

@app.route('/api/repos/add', methods=['POST'])
def add_new_repo():
    try:
        data = request.json
        name = data.get('name')
        old_name = data.get('old_name')

        if not name: 
            return jsonify({"error": "Missing name"}), 400
        
        if old_name and old_name != name:
            delete_repo_entry(old_name)

        config_data = {k:v for k,v in data.items() if k not in ['name', 'old_name']}
        add_repo_entry(name, config_data)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/repos/delete', methods=['POST'])
def remove_repo():
    try:
        data = request.json
        name = data.get('name')
        delete_repo_entry(name)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/edit_ftp_port', methods=['POST'])
def edit_ftp_port():
    new_content = request.json.get('content')
    update_config("ftp_port", new_content)
    return "Settings updated!"

@app.route('/tools/update_download0', methods=['POST'])
def run_update_download0():
    config = get_config()
    ip = config.get("ip")
    port = config.get("ftp_port", "1337")
    
    if not ip:
        return jsonify({"success": False, "message": "IP Address not set"}), 400

    print(f"[TOOL] Installing download0.dat to {ip}...")
    success, message = auto_replace_download0(ip, port)
    
    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": message}), 500

@app.route('/tools/block_updates', methods=['POST'])
def run_block_updates():
    config = get_config()
    ip = config.get("ip")
    port = config.get("ftp_port", "1337")
    
    if not ip:
        return jsonify({"success": False, "message": "IP Address not set"}), 400

    print(f"[TOOL] Blocking updates on {ip}...")
    success, message = patch_blocker(ip, port)
    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": message}), 500

@app.route('/credits')
def credits_page():
    return render_template('credits.html')

@app.route('/settings')
def settings_page():
    return render_template('settings.html')

@app.route('/api/settings', methods=['GET', 'POST'])
def handle_settings():
    if request.method == 'GET':
        return jsonify(get_config())
    
    if request.method == 'POST':
        try:
            new_settings = request.get_json()
            current_config = get_config()
            
            valid_keys = [
                'ip', 'ajb', 'ftp_port', 'loader_port', 'voidshell_port', 'global_delay', 
                'ui_animations', 'kstuff', 'debug_mode', 
                'auto_update_repos', 'dns_auto_start', 'compact_mode'
            ]
            for key in valid_keys:
                if key in new_settings:
                    current_config[key] = str(new_settings[key])
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(current_config, f, indent=4)
                
            return jsonify({"success": True, "message": "Settings saved successfully"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/check_loader')
def check_loader():
    """Test if the loader port is open on the PS5 (from this server's network)."""
    try:
        ip = (request.args.get('ip') or get_config().get('ip', '')).strip()
        port_str = request.args.get('port') or get_config().get('loader_port', '50000')
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            port = 50000
        if not ip:
            return jsonify({"success": False, "error": "No IP provided"}), 400
        open_ = is_port_open(ip, port, timeout=3)
        return jsonify({"success": True, "open": open_, "ip": ip, "port": port})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/network_info')
def network_info():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
    except:
        server_ip = "Unknown"
    
    client_ip = request.remote_addr
    
    return jsonify({
        "server_ip": server_ip,
        "client_ip": client_ip
    })

@app.route('/ftp')
def ftp_page():
    return render_template('ftp.html')

@app.route('/api/ftp/list', methods=['POST'])
def api_ftp_list():
    config = get_config()
    ip = config.get("ip")
    port = config.get("ftp_port", "1337")
    path = request.json.get('path', '/')
    
    if not ip:
        return jsonify({"success": False, "error": "IP not configured"}), 400
        
    result = list_ftp_directory(ip, port, path)
    if result['success']:
        return jsonify(result)
    else:
        return jsonify(result), 500

@app.route('/api/ftp/download_file', methods=['POST'])
def api_ftp_download():
    config = get_config()
    ip = config.get("ip")
    port = config.get("ftp_port", "1337")
    path = request.json.get('path')
    
    result = download_file_content(ip, port, path)
    if result['success']:
        if request.json.get('as_text'):
            try:
                return jsonify({"success": True, "content": result['content'].decode('utf-8')})
            except:
                return jsonify({"success": False, "error": "Could not decode file as text"})
        
        filename = os.path.basename(path)
        return send_file(
            io.BytesIO(result['content']),
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
    return jsonify(result), 500

@app.route('/api/ftp/upload_file', methods=['POST'])
def api_ftp_upload():
    config = get_config()
    ip = config.get("ip")
    port = config.get("ftp_port", "1337")
    
    path = request.form.get('path')
    file = request.files.get('file')
    
    text_content = request.form.get('content')
    
    if text_content is not None:
        result = upload_file_content(ip, port, path, text_content.encode('utf-8'))
        return jsonify(result)

    if file:
        file_content = file.read()
        filename = secure_filename(file.filename)
        full_path = f"{path.rstrip('/')}/{filename}"
        result = upload_file_content(ip, port, full_path, file_content)
        return jsonify(result)
        
    return jsonify({"success": False, "error": "No data provided"}), 400

@app.route('/api/ftp/action', methods=['POST'])
def api_ftp_action():
    config = get_config()
    ip = config.get("ip")
    port = config.get("ftp_port", "1337")
    
    data = request.json
    action = data.get('action')
    path = data.get('path')
    
    if action == 'delete':
        return jsonify(delete_item(ip, port, path, data.get('is_dir', False)))
    elif action == 'mkdir':
        return jsonify(create_directory(ip, port, path))
    elif action == 'rename':
        return jsonify(rename_item(ip, port, path, data.get('new_path')))
        
    return jsonify({"success": False, "error": "Invalid action"}), 400

@app.route('/dns')
def dns_page():
    return render_template('dns.html')

@app.route('/api/dns/list')
def api_dns_list():
    return jsonify(get_dns_rules())

@app.route('/api/dns/add', methods=['POST'])
def api_dns_add():
    try:
        data = request.json
        name = data.get('name')
        domain = data.get('domain')
        target = data.get('target', '0.0.0.0')

        if not name or not domain:
            return jsonify({"error": "Name and Domain are required"}), 400

        rules = get_dns_rules()
        new_rule = {
            "id": str(uuid.uuid4()),
            "name": name,
            "domain": domain,
            "target": target
        }
        rules.append(new_rule)
        save_dns_rules(rules)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/dns/delete', methods=['POST'])
def api_dns_delete():
    try:
        rule_id = request.json.get('id')
        rules = get_dns_rules()
        rules = [r for r in rules if r.get('id') != rule_id]
        save_dns_rules(rules)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# BackPork endpoints (our integration: FTP, patch-from-GitHub, fakelib)
@app.route('/backpork')
def backpork_page():
    return render_template('backpork.html')

@app.route('/account-activator')
def account_activator_page():
    return render_template('account_activator.html')

@app.route('/voidshell')
def voidshell_page():
    config = get_config()
    ps5_ip = (config.get('ip') or '').strip()
    voidshell_port = config.get('voidshell_port') or '7007'
    try:
        int(voidshell_port)
    except (ValueError, TypeError):
        voidshell_port = '7007'
    y2jb_home_url = (request.url_root or 'http://172.16.0.28:8000/').rstrip('/')
    return render_template('voidshell.html', ps5_ip=ps5_ip, voidshell_port=voidshell_port, y2jb_home_url=y2jb_home_url)

# In-memory cache for voidshell proxy (assets only) to speed up icon loading
_voidshell_proxy_cache = {}
_VOIDSHELL_CACHE_TTL = 300  # 5 min for assets
_VOIDSHELL_CACHE_MAX = 500   # max entries

@app.route('/api/voidshell_proxy/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def voidshell_proxy(subpath):
    """Proxy requests to voidshell.elf on PS5 to avoid CORS (browser blocks cross-origin to PS5)."""
    config = get_config()
    ip = (config.get('ip') or '').strip()
    port = config.get('voidshell_port') or '7007'
    try:
        int(port)
    except (ValueError, TypeError):
        port = '7007'
    if not ip:
        return jsonify({"error": "PS5 IP not set in Settings"}), 400
    base = f"http://{ip}:{port}"
    url = f"{base}/{subpath}"
    if request.query_string:
        url += '?' + request.query_string.decode()
    cache_key = None
    asset_headers = {}
    if request.method == 'GET' and subpath.startswith('assets/'):
        cache_key = url
        # Let the browser cache icons/pics so we don't re-fetch every time (avoids slow re-cache)
        asset_headers = {'Cache-Control': 'public, max-age=86400'}  # 1 day
        if cache_key in _voidshell_proxy_cache:
            entry = _voidshell_proxy_cache[cache_key]
            if entry and (time.time() - entry['ts']) < _VOIDSHELL_CACHE_TTL:
                resp = Response(entry['content'], status=entry['status'], mimetype=entry.get('mimetype', 'application/octet-stream'))
                resp.headers['Cache-Control'] = 'public, max-age=86400'
                return resp
    try:
        kwargs = {"timeout": 30}
        if request.method in ('POST', 'PUT', 'PATCH') and request.get_data():
            kwargs["data"] = request.get_data()
            if request.content_type:
                kwargs["headers"] = {'Content-Type': request.content_type}
        r = requests.request(request.method, url, **kwargs)
        if cache_key and r.status_code == 200 and len(r.content) < 5 * 1024 * 1024:
            while len(_voidshell_proxy_cache) >= _VOIDSHELL_CACHE_MAX:
                oldest = min(_voidshell_proxy_cache.items(), key=lambda x: x[1]['ts'])
                del _voidshell_proxy_cache[oldest[0]]
            _voidshell_proxy_cache[cache_key] = {
                'content': r.content, 'status': r.status_code,
                'mimetype': r.headers.get('Content-Type', 'application/octet-stream'), 'ts': time.time()
            }
        resp = Response(r.content, status=r.status_code, mimetype=r.headers.get('Content-Type', 'application/octet-stream'))
        resp.headers.update(asset_headers)
        return resp
    except requests.exceptions.ConnectTimeout:
        return jsonify({"error": "Connection to PS5 timed out"}), 504
    except requests.exceptions.ConnectionError as e:
        return jsonify({"error": "Cannot reach PS5 (voidshell.elf not running?)", "detail": str(e)}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 502

@app.route('/api/backpork/test_ftp', methods=['POST'])
def api_backpork_test_ftp():
    """Test FTP connection to PS5"""
    try:
        config = get_config()
        ip = config.get("ip")
        port = config.get("ftp_port", "1337")
        
        if not ip:
            return jsonify({"success": False, "error": "IP Address not set"}), 400
        
        # Try to connect and list root directory
        from src.backpork_manager import get_ftp_connection
        ftp = None
        try:
            ftp = get_ftp_connection(ip, port)
            # Try to list root directory
            ftp.retrlines('LIST', lambda x: None)
            ftp.quit()
            return jsonify({"success": True, "message": f"FTP connection successful to {ip}:{port}"})
        except Exception as e:
            error_msg = str(e)
            if "Connection refused" in error_msg or "10061" in error_msg:
                return jsonify({
                    "success": False, 
                    "error": f"FTP server not running. Make sure:\n1. Send ftpsrv-ps5.elf payload from the main page\n2. Wait a few seconds after sending\n3. Check that port {port} is correct"
                }), 500
            else:
                return jsonify({"success": False, "error": error_msg}), 500
        finally:
            if ftp:
                try:
                    ftp.quit()
                except:
                    pass
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/backpork/list_games', methods=['POST'])
def api_backpork_list_games():
    try:
        config = get_config()
        ip = config.get("ip")
        port = config.get("ftp_port", "1337")
        
        if not ip:
            return jsonify({"success": False, "error": "IP Address not set"}), 400
        
        result = list_installed_games(ip, port)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/backpork/create_fakelib', methods=['POST'])
def api_backpork_create_fakelib():
    try:
        config = get_config()
        ip = config.get("ip")
        port = config.get("ftp_port", "1337")
        data = request.json
        game_path = data.get('game_path')
        title_id = data.get('title_id')  # Extract title_id from game object
        
        if not ip:
            return jsonify({"success": False, "error": "IP Address not set"}), 400
        if not game_path:
            return jsonify({"success": False, "error": "Game path not provided"}), 400
        
        logger.info("=" * 60)
        logger.info("/api/backpork/create_fakelib called")
        logger.info(f"game_path={game_path}")
        logger.info(f"title_id={title_id}")
        logger.info(f"IP={ip}, Port={port}")
        logger.info("=" * 60)
        sys.stdout.flush()
        sys.stderr.flush()
        
        result = create_fakelib_folder(ip, port, game_path, title_id)
        
        logger.info("=" * 60)
        logger.info("/api/backpork/create_fakelib result")
        logger.info(f"success={result.get('success')}")
        logger.info(f"message={result.get('message')}")
        logger.info(f"error={result.get('error')}")
        logger.info(f"path={result.get('path')}")
        logger.info("=" * 60)
        sys.stdout.flush()
        sys.stderr.flush()
        
        return jsonify(result)
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[API] Exception in create_fakelib: {e}")
        print(f"[API] Traceback: {error_trace}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/backpork/test_code', methods=['GET'])
def api_backpork_test_code():
    """Test endpoint to verify code is running"""
    import src.backpork_manager
    import inspect
    source_file = inspect.getsourcefile(src.backpork_manager.create_fakelib_folder)
    with open(source_file, 'r') as f:
        lines = f.readlines()
        # Check if line 258 has the new logging
        if len(lines) > 257 and '[FAKELIB] ==========' in lines[257]:
            return jsonify({"success": True, "message": "New code is loaded", "line_258": lines[257].strip()})
        else:
            return jsonify({"success": False, "message": "Old code might be running", "line_258": lines[257].strip() if len(lines) > 257 else "N/A"})

@app.route('/api/backpork/discover_paths', methods=['POST'])
def api_backpork_discover_paths():
    """Discover where games are actually stored"""
    try:
        config = get_config()
        ip = config.get("ip")
        port = config.get("ftp_port", "1337")
        
        if not ip:
            return jsonify({"success": False, "error": "IP Address not set"}), 400
        
        from src.backpork_manager import get_ftp_connection
        import ftplib
        
        ftp = None
        accessible_paths = []
        game_directories = []
        
        try:
            ftp = get_ftp_connection(ip, port)
            
            # List of potential base paths to check
            potential_paths = [
                "/data", "/data/games", "/data/homebrew", "/data/etaHEN", "/data/etaHEN/games",
                "/mnt", "/mnt/ext0", "/mnt/ext0/games", "/mnt/ext0/homebrew", "/mnt/ext0/etaHEN",
                "/user", "/user/app",
            ]
            
            # Add USB paths
            for usb_num in range(8):
                potential_paths.extend([
                    f"/mnt/usb{usb_num}",
                    f"/mnt/usb{usb_num}/games",
                    f"/mnt/usb{usb_num}/homebrew",
                    f"/mnt/usb{usb_num}/etaHEN",
                    f"/mnt/usb{usb_num}/etaHEN/games",
                ])
            
            for path in potential_paths:
                try:
                    ftp.cwd(path)
                    lines = []
                    ftp.retrlines('LIST', lines.append)
                    accessible_paths.append({
                        "path": path,
                        "item_count": len(lines),
                        "items": [line.split()[-1] for line in lines[:10]]  # First 10 items
                    })
                    
                    # Check if any items look like game directories (PPSA or CUSA)
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 9:
                            name = parts[-1]
                            if (name.startswith('PPSA') or name.startswith('CUSA')) and parts[0].startswith('d'):
                                game_directories.append({
                                    "path": f"{path}/{name}",
                                    "title_id": name
                                })
                except:
                    pass
            
            return jsonify({
                "success": True,
                "accessible_paths": accessible_paths,
                "game_directories": game_directories
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
        finally:
            if ftp:
                try:
                    ftp.quit()
                except:
                    pass
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/backpork/process_libraries', methods=['POST'])
def api_backpork_process_libraries():
    try:
        config = get_config()
        ip = config.get("ip")
        port = config.get("ftp_port", "1337")
        data = request.json
        firmware = data.get('firmware')  # '6xx' or '7xx'
        game_path = data.get('game_path')
        selected_libs = data.get('libraries', list(REQUIRED_LIBS.keys()))  # List of library names to process
        
        if not ip:
            return jsonify({"success": False, "error": "IP Address not set"}), 400
        if not firmware:
            return jsonify({"success": False, "error": "Firmware version not selected"}), 400
        if not game_path:
            return jsonify({"success": False, "error": "Game path not provided"}), 400
        
        results = []
        print(f"\n[BACKPORK] ========== Starting library processing ==========")
        print(f"[BACKPORK] IP: {ip}, Port: {port}")
        print(f"[BACKPORK] Firmware: {firmware}, Game path: {game_path}")
        print(f"[BACKPORK] Libraries to process: {selected_libs}")
        print(f"[BACKPORK] ===================================================\n")
        
        for lib_name in selected_libs:
            print(f"\n[BACKPORK] Processing library: {lib_name}")
            print(f"[BACKPORK] ===================================================")
            try:
                result = process_library_for_game(ip, port, lib_name, firmware, game_path)
                print(f"[BACKPORK] Result for {lib_name}: success={result.get('success')}, error={result.get('error')}")
                results.append({
                    "library": lib_name,
                    "success": result.get("success", False),
                    "message": result.get("message") or result.get("error", "Unknown error"),
                    "steps": result.get("steps", [])
                })
                if result.get("success"):
                    print(f"[BACKPORK] ✓ {lib_name} processed successfully")
                else:
                    error_msg = result.get('error', 'Unknown error')
                    print(f"[BACKPORK] ✗ {lib_name} failed: {error_msg}")
                    sys.stdout.flush()
            except Exception as e:
                import traceback
                error_trace = traceback.format_exc()
                print(f"[BACKPORK] ✗✗✗ EXCEPTION processing {lib_name}: {e}")
                print(f"[BACKPORK] Full traceback:")
                print(error_trace)
                sys.stdout.flush()
                sys.stderr.flush()
                results.append({
                    "library": lib_name,
                    "success": False,
                    "message": f"Exception: {str(e)}",
                    "steps": []
                })
        
        all_success = all(r["success"] for r in results)
        return jsonify({
            "success": all_success,
            "results": results
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/update', methods=['POST'])
def api_update():
    """Update Y2JB-WebUI from git repository"""
    try:
        import subprocess
        
        # Get the directory where server.py is located (Y2JB-WebUI)
        webui_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Check if it's a git repository
        git_dir = os.path.join(webui_dir, '.git')
        if not os.path.exists(git_dir):
            return jsonify({
                "success": False,
                "error": "Not a git repository. Cannot update."
            }), 400
        
        # Change to the webui directory
        original_cwd = os.getcwd()
        os.chdir(webui_dir)
        
        try:
            # Fetch latest changes
            fetch_result = subprocess.run(
                ['git', 'fetch', 'origin'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if fetch_result.returncode != 0:
                return jsonify({
                    "success": False,
                    "error": f"Git fetch failed: {fetch_result.stderr}"
                }), 500
            
            # Check current branch
            branch_result = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                capture_output=True,
                text=True,
                timeout=10
            )
            current_branch = branch_result.stdout.strip() if branch_result.returncode == 0 else 'main'
            
            # Get status before pull
            status_before = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                capture_output=True,
                text=True,
                timeout=10
            )
            commit_before = status_before.stdout.strip() if status_before.returncode == 0 else 'unknown'
            
            # Pull latest changes
            pull_result = subprocess.run(
                ['git', 'pull', 'origin', current_branch],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Get status after pull
            status_after = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                capture_output=True,
                text=True,
                timeout=10
            )
            commit_after = status_after.stdout.strip() if status_after.returncode == 0 else 'unknown'
            
            if pull_result.returncode != 0:
                return jsonify({
                    "success": False,
                    "error": f"Git pull failed: {pull_result.stderr}",
                    "output": pull_result.stdout
                }), 500
            
            # Check if there were changes
            updated = commit_before != commit_after
            
            return jsonify({
                "success": True,
                "updated": updated,
                "commit_before": commit_before[:8] if commit_before != 'unknown' else None,
                "commit_after": commit_after[:8] if commit_after != 'unknown' else None,
                "branch": current_branch,
                "output": pull_result.stdout,
                "message": "Updated successfully" if updated else "Already up to date"
            })
            
        finally:
            os.chdir(original_cwd)
            
    except subprocess.TimeoutExpired:
        return jsonify({
            "success": False,
            "error": "Update operation timed out. Please try again."
        }), 500
    except Exception as e:
        import traceback
        return jsonify({
            "success": False,
            "error": f"Update failed: {str(e)}",
            "traceback": traceback.format_exc()
        }), 500

@app.route('/logs')
def logs_page():
    return render_template('logs.html')

@app.route('/api/logs')
def api_logs():
    return jsonify({"logs": get_logs()})

@app.route('/system')
def system_page():
    return render_template('system.html')

@app.route('/api/system/stats')
def api_system_stats():
    return jsonify(get_system_stats())

@app.route('/api/system/power', methods=['POST'])
def api_system_power():
    data = request.json
    action = data.get('action')
    
    if action not in ['reboot', 'shutdown']:
        return jsonify({"success": False, "error": "Invalid action"}), 400
        
    success, message = power_control(action)
    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "error": message}), 500

if __name__ == "__main__":
    config = get_config()
    
    setup_logging(config)
    
    # nu ka dede
    debug_mode = config.get("debug_mode") == "true"
    is_reloader_process = os.environ.get("WERKZEUG_RUN_MAIN") == "true"

    # tikiuosi kad veiks, nemanau bet ok 
    # debug ijungtas = tada reloaderio prcoesssasassasasasassas.
    if not debug_mode or is_reloader_process:
        run_startup_tasks(config)

        threading.Thread(target=check_ajb, daemon=True).start()

        # permetu dns kad nemaisytu ajb ir kitas funkcijas, nes gali buti problemu su threading ir flask debug mode
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("1.1.1.1", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "127.0.0.1"

        if config.get("dns_auto_start", "true") == "true":
            print(f"--- Initializing DNS Server on {local_ip} ---")
            dns_service = DNSServer(config_file=DNS_CONFIG_FILE, host_ip=local_ip)
            threading.Thread(target=dns_service.start, daemon=True).start()
        else:
            print("[STARTUP] DNS Server disabled by settings")

    app.run(host="0.0.0.0", port=8000, debug=debug_mode)