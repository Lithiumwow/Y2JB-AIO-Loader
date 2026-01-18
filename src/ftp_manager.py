import ftplib
import os
import io
import re

def get_ftp_connection(ip, port):
    ftp = ftplib.FTP()
    ftp.connect(ip, int(port), timeout=10)
    ftp.login('', '')
    return ftp

def parse_ftp_list_line(line):
    parts = re.split(r'\s+', line, maxsplit=8)
    if len(parts) < 9:
        return None

    perms = parts[0]
    is_dir = perms.startswith('d')
    size = parts[4]
    name = parts[-1]
    return {
        "name": name,
        "type": "dir" if is_dir else "file",
        "size": size,
        "raw": line
    }

def list_ftp_directory(ip, port, path='/'):
    ftp = None
    try:
        ftp = get_ftp_connection(ip, port)
        ftp.cwd(path)
        lines = []
        ftp.retrlines('LIST', lines.append)
        items = []
        for line in lines:
            parsed = parse_ftp_list_line(line)
            if parsed and parsed['name'] not in ['.', '..']:
                items.append(parsed)
        items.sort(key=lambda x: (x['type'] != 'dir', x['name'].lower()))
        return {"success": True, "path": path, "items": items}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        if ftp:
            try: ftp.quit()
            except: pass

def download_file_content(ip, port, path):
    ftp = None
    try:
        ftp = get_ftp_connection(ip, port)
        buffer = io.BytesIO()
        ftp.retrbinary(f"RETR {path}", buffer.write)
        buffer.seek(0)
        return {"success": True, "content": buffer.getvalue()}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        if ftp:
            try: ftp.quit()
            except: pass

def upload_file_content(ip, port, path, file_content):
    ftp = None
    try:
        ftp = get_ftp_connection(ip, port)
        ftp.storbinary(f"STOR {path}", io.BytesIO(file_content))
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        if ftp:
            try: ftp.quit()
            except: pass

def delete_item(ip, port, path, is_dir=False):
    ftp = None
    try:
        ftp = get_ftp_connection(ip, port)
        if is_dir:
            ftp.rmd(path)
        else:
            ftp.delete(path)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        if ftp:
            try: ftp.quit()
            except: pass

def create_directory(ip, port, path):
    ftp = None
    try:
        ftp = get_ftp_connection(ip, port)
        ftp.mkd(path)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        if ftp:
            try: ftp.quit()
            except: pass

def rename_item(ip, port, old_path, new_path):
    ftp = None
    try:
        ftp = get_ftp_connection(ip, port)
        ftp.rename(old_path, new_path)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        if ftp:
            try: ftp.quit()
            except: pass