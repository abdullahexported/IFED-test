# IFED – IoT Forensic Extraction Device  
**Version 1.3.0.IoT**

Lightweight, open-source GUI for acquiring, sealing, verifying and reporting IoT evidence in one offline workflow.

---

## Features
- Live acquisition: simulated logs OR real USB/serial stream  
- Cryptographic sealing: SHA-256 & MD5 baseline stored with evidence  
- Tamper-evident integrity check (re-hash and compare)  
- Automatic timeline reconstruction (sorted by epoch)  
- One-click PDF forensic report (ReportLab, A4, page numbered)  
- Dark-mode Tkinter interface; runs on Windows, Linux, macOS  
- All evidence stays local—no cloud, no uploads

---

## Quick Start
```bash
git clone https://github.com/YOUR_USER/IFED.git
cd IFED
pip install -r requirements.txt
python ifed.py
```

---

## Requirements
- Python 3.8+  
- `pyserial==3.5`  
- `reportlab==4.0.4`  

---

## Usage Snapshot
1. **Acquisition**: choose “Simulated” or plug in IoT device → Start → Stop & Seal  
2. **Encryption**: optional base64 view  
3. **Review**: inspect sealed JSON + baseline hashes  
4. **Integrity**: re-compute hashes → green “VERIFIED” or red “FAILED”  
5. **Reconstruction**: human-readable timeline  
6. **Report**: enter Case ID & Investigator → generate signed PDF

---

## Folder Layout
```
IFED/
├── ifed.py              # main GUI
├── requirements.txt
├── README.md
├── .gitignore
└── evidence/            # created at runtime (logs)
└── reports/             # created at runtime (PDFs)
```

---

## Legal & License
Academic / research / forensic use only.  
This tool does **not** modify original evidence.  
Final interpretation rests with the investigator.  
Released under MIT License – see LICENSE file.

---

## Contributing
Pull-requests welcome: bug-fixes, additional parsers, UI translations, new report templates.  
Open an issue first to discuss large changes.

---

## Acknowledgements
Built with Python, Tkinter, ReportLab, PySerial.
