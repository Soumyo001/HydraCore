# progressive_0verload


### payloads
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
	C --> D[nssm root_mon checker service installer]
	D --> |create root_mon_mon.ps1 service|E[root_mon_mon.ps1/monitoring root_mon service as a service]
	E --> F{is root_mon service alive?}
	F --> |YES|CON2[continue monitoring]
	F --> |NO|G[nssm root_mon service installer]
	G --> |create root_mon.ps1 service|MON[root_mon/monitoring root service as a service]
	I --> |make root script as service|J[root]
	MON --> H{is root service alive?}
	H --> |YES|CON[continue monitoring]
	H --> |NO|I[nssm root service installer]
	J --> K[memory_hog]
	J --> L[cpu_hog]
	J --> M[storage_hog]
```

