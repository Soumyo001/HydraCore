
## payloads
- **root (the mother_script to control all)**
	- **cpu_hog**
	- **memory_hog**
	- **storage_hog (not-ready)**

- **root service adjoints**
	- **root_mon.ps1**
	- **root_mon_mon.ps1**

- **fwd (fuck_windows_defender)**
	- **fwd_mon.ps1**
	- **fwd.ps1 (might use an .exe instead)**

- **end game scripts**
	- **warning.vbs**
	- **riddle.vbs**
	- **fun.vbs**
	- **fun_final.vbs**

- **Installers**
	- **batdropper**
	- **duckey-logger(haven't worked on that idea)**
	- **shellcode**
	- **trojan (shellcode embedding)**
	- **dll-hijacking(make the installer a dll...maybe?)**

### Process Flow

```mermaid
graph TD
	A[installer] --> B[UAC prompt/bypass script]
	B --> C[init.exe]
	C --> D[init_service_rootmonmon.ps1]
	C --> finde("email_worm(finde.exe)")
	C --> http("http_worm(http.exe)")
	C --> ftp("ftp_worm(ftp.exe)")
	C --> usb("usb_worm(usb.exe)")
	C --> N[nssm fwd_mon service installer]
	D --> |"create root_mon_mon.ps1 service(Exsanguinate)"|E[root_mon_mon.ps1]
	N --> |"Create fwd_mon.ps1 service(Disenfranchise)"|O[fwd_mon.ps1]
	O --> CHECK
	O --> P{is fwd.ps1 deleted?}
	P --> |YES|R[nssm fwd service installer]
	P --> |NO|Q{is fwd service alive?}
	Q --> |NO|R
	Q --> |YES|CON3[continue monitoring]
	R --> |"create fwd.ps1 service(Vanguard)"|S[fwd.ps1]
	E --> T{is root_mon.ps1 deleted?}
	T --> |YES|G[nssm root_mon service installer]
	T --> |NO|F{is root_mon service alive?}
	F --> |NO|G
	F --> |YES|CON2[continue monitoring]
	G --> |"create root_mon.ps1 service(Lugubrious)"|MON[root_mon.ps1]
	MON --> U{is root.ps1 deleted?}
	U --> |YES|I[nssm root service installer]
	I --> |"create root.ps1 service(Peregrinate)"|J[root.ps1]
	U --> |NO|H{is root service alive?}
	H --> |NO|I
	H --> |YES|CON[continue monitoring]
	J --> K[memory_hog]
	J --> L[cpu_hog]
	J --> M[storage_hog]
	E --> CHECK{is any parameter empty?} 
	MON --> CHECK
	J --> CHECK
	CHECK --> |YES|W[warning.vbs]
	W --> X[riddle.vbs]
	X --> RID{riddle answer}
	RID --> |CORRECT ANSWER|REM[remove.ps1]
	RID --> |SILENT ANSWER|FUN[fun.vbs]
	RID --> |FALSE ANSWER|FUN_FINAL[fun_final.vbs]
```
