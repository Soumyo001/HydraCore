
## payloads
- **root (the mother_script to control all)**
	- **cpu_hog**
	- **memory_hog**
	- **storage_hog (not-ready)**

- **Installers**
	- **batdropper**
	- **duckey-logger(haven't worked on that idea)**
	- **shellcode**
	- **trojan (shellcode embedding)**
	- **dll-hijacking(make the installer a dll...maybe?)**

### Execution Flow

```mermaid
graph TD
	A[installer] --> B[UAC prompt/bypass script]
	B --> C[Admin elevated script]
	C --> D[nssm root_mon_mon service installer]
	C --> N[nssm fwd_mon service installer]
	D --> |create root_mon_mon.ps1 service|E[root_mon_mon.ps1/monitoring root_mon service as a service]
	N --> |Create fwd_mon.ps1 service|O[fwd_mon.ps1]
	O --> P{is fwd.ps1 deleted?}
	P --> |YES|R[nssm fwd service installer]
	P --> |NO|Q{is fwd service alive?}
	Q --> |YES|CON3[continue monitoring]
	Q --> |NO|R
	R --> |create fwd.ps1 service|S[fwd.ps1]
	E --> T{is root_mon.ps1 deleted?}
	T --> |YES|G[nssm root_mon service installer]
	T --> |NO|F{is root_mon service alive?}
	F --> |YES|CON2[continue monitoring]
	F --> |NO|G
	G --> |create root_mon.ps1 service|MON[root_mon.ps1/monitoring root service as a service]
	MON --> U{is root.ps1 deleted?}
	U --> |YES|I[nssm root service installer]
	I --> |make root.ps1 as service|J[root.ps1]
	U --> |NO|H{is root service alive?}
	H --> |YES|CON[continue monitoring]
	H --> |NO|I
	J --> K[memory_hog]
	J --> L[cpu_hog]
	J --> M[storage_hog]
```
