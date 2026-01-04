import tkinter as tk
from tkinter import filedialog, messagebox
import json, time, random, base64, hashlib, os, uuid
import serial
import serial.tools.list_ports

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor, black

# =====================================================
# TOOL METADATA
# =====================================================
TOOL_NAME = "IFED – IoT Forensic Extraction Device"
VERSION = "1.3.0.IoT"

# =====================================================
# PATHS
# =====================================================
BASE_PATH = "D:/IoT_Evidence_Project/"
LOG_PATH = BASE_PATH + "evidence/logs/"
REPORT_PATH = BASE_PATH + "reports/"
os.makedirs(LOG_PATH, exist_ok=True)
os.makedirs(REPORT_PATH, exist_ok=True)

# =====================================================
# GLOBAL STATE
# =====================================================
logs = []
sealed_log_file = None
imported_log_source = "N/A"

baseline_md5 = ""
baseline_sha256 = ""
verify_md5 = ""
verify_sha256 = ""
integrity_status = "NOT VERIFIED"

reconstruction_result = ""

serial_number = f"IFED-{time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

# =====================================================
# UI COLORS
# =====================================================
BG = "#0f172a"
PANEL = "#111827"
CARD = "#1f2933"
TEXT = "#e5e7eb"
ACCENT = "#38bdf8"
ACTIVE = "#2563eb"
OK = "#22c55e"
FAIL = "#ef4444"

# =====================================================
# HASH UTIL
# =====================================================
def compute_hash_from_file(path):
    with open(path, "rb") as f:
        data = f.read()
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()

# =====================================================
# SERIAL UTIL
# =====================================================
def list_serial_ports():
    return serial.tools.list_ports.comports()

# =====================================================
# MAIN WINDOW
# =====================================================
root = tk.Tk()
root.title(f"{TOOL_NAME} | Version {VERSION}")
root.geometry("1200x760")
root.configure(bg=BG)

# =====================================================
# SIDEBAR
# =====================================================
sidebar = tk.Frame(root, bg=PANEL, width=260)
sidebar.pack(side="left", fill="y")

tk.Label(sidebar, text="IFED", fg=ACCENT, bg=PANEL,
         font=("Segoe UI", 20, "bold")).pack(pady=20)

nav_buttons = {}

def highlight(step):
    for b in nav_buttons.values():
        b.config(bg=CARD)
    nav_buttons[step].config(bg=ACTIVE)

def nav_btn(text, step):
    btn = tk.Button(
        sidebar, text=text,
        command=lambda: (highlight(step), show_page(step)),
        bg=CARD, fg=TEXT, relief="flat",
        font=("Segoe UI", 11), width=24, pady=8
    )
    btn.pack(pady=4)
    nav_buttons[step] = btn

# =====================================================
# PAGE CONTAINER
# =====================================================
container = tk.Frame(root, bg=BG)
container.pack(side="left", fill="both", expand=True)

pages = {}

def show_page(name):
    for p in pages.values():
        p.pack_forget()
    pages[name].pack(fill="both", expand=True)

# =====================================================
# PAGE 1 – ACQUISITION & SEALING
# =====================================================
def page_acquisition():
    frame = tk.Frame(container, bg=BG)

    tk.Label(frame, text="1. Evidence Acquisition & Sealing",
             fg=TEXT, bg=BG, font=("Segoe UI", 18, "bold")).pack(anchor="w")

    mode = tk.StringVar(value="SIMULATED")

    mode_frame = tk.Frame(frame, bg=BG)
    mode_frame.pack(anchor="w", pady=5)

    tk.Radiobutton(mode_frame, text="Simulated IoT Logs",
                   variable=mode, value="SIMULATED",
                   bg=BG, fg=TEXT, selectcolor=BG).pack(side="left", padx=10)

    tk.Radiobutton(mode_frame, text="Hardware Device (USB)",
                   variable=mode, value="HARDWARE",
                   bg=BG, fg=TEXT, selectcolor=BG).pack(side="left", padx=10)

    display = tk.Text(frame, bg=CARD, fg=TEXT, font=("Consolas", 10))
    display.pack(fill="both", expand=True, pady=10)

    # ---------- SIMULATED ----------
    running = {"state": False}

    def gen_log():
        return {
            "source": "Simulated IoT Device",
            "value": random.randint(10, 100),
            "timestamp": time.time()
        }

    def start_sim():
        global logs, imported_log_source
        if mode.get() != "SIMULATED":
            return
        logs = []
        imported_log_source = "Simulated IoT Logs"
        running["state"] = True
        collect()

    def collect():
        if running["state"]:
            logs.append(gen_log())
            display.delete("1.0", tk.END)
            display.insert(tk.END, json.dumps(logs, indent=2))
            frame.after(2000, collect)

    def stop_seal_sim():
        global sealed_log_file, baseline_md5, baseline_sha256
        running["state"] = False
        if not logs:
            messagebox.showerror("Error", "No logs collected")
            return
        fname = f"IFED_Simulated_{time.strftime('%Y%m%d_%H%M%S')}.json"
        sealed_log_file = LOG_PATH + fname
        with open(sealed_log_file, "w") as f:
            json.dump(logs, f, indent=2)
        baseline_md5, baseline_sha256 = compute_hash_from_file(sealed_log_file)
        messagebox.showinfo("Evidence Sealed", "Simulated logs sealed")

    # ---------- HARDWARE ----------
    serial_frame = tk.Frame(frame, bg=BG)
    serial_frame.pack(anchor="w")

    port_var = tk.StringVar()
    port_menu = tk.OptionMenu(serial_frame, port_var, "")
    port_menu.pack(side="left")

    def refresh_ports():
        menu = port_menu["menu"]
        menu.delete(0, "end")
        ports = list_serial_ports()
        for p in ports:
            menu.add_command(
                label=f"{p.device} - {p.description}",
                command=lambda v=p.device: port_var.set(v)
            )
        if ports:
            port_var.set(ports[0].device)

    tk.Button(serial_frame, text="Refresh Ports",
              command=refresh_ports).pack(side="left", padx=5)
    refresh_ports()

    def import_hw():
        global logs, sealed_log_file, baseline_md5, baseline_sha256, imported_log_source
        if mode.get() != "HARDWARE":
            return
        port = port_var.get()
        ser = serial.Serial(port, 9600, timeout=2)
        logs = []
        imported_log_source = f"Hardware Device ({port})"
        display.delete("1.0", tk.END)
        start = time.time()
        while time.time() - start < 10:
            try:
                line = ser.readline().decode(errors="ignore").strip()
                if line.startswith("{"):
                    logs.append(json.loads(line))
                    display.insert(tk.END, line + "\n")
            except:
                continue
        ser.close()
        fname = f"IFED_Hardware_{time.strftime('%Y%m%d_%H%M%S')}.json"
        sealed_log_file = LOG_PATH + fname
        with open(sealed_log_file, "w") as f:
            json.dump(logs, f, indent=2)
        baseline_md5, baseline_sha256 = compute_hash_from_file(sealed_log_file)
        messagebox.showinfo("Acquisition Complete", "Hardware logs sealed")

    btns = tk.Frame(frame, bg=BG)
    btns.pack()

    tk.Button(btns, text="Start Simulated", command=start_sim).pack(side="left", padx=5)
    tk.Button(btns, text="Stop & Seal Simulated", command=stop_seal_sim).pack(side="left", padx=5)
    tk.Button(btns, text="Import Hardware Logs", command=import_hw).pack(side="left", padx=5)

    return frame

# =====================================================
# PAGE 2 – ENCRYPTION
# =====================================================
def page_encryption():
    frame = tk.Frame(container, bg=BG)
    tk.Label(frame, text="2. Encryption (View)",
             fg=TEXT, bg=BG, font=("Segoe UI", 18, "bold")).pack(anchor="w")
    box = tk.Text(frame, bg=CARD, fg=TEXT)
    box.pack(fill="both", expand=True)
    def encrypt():
        box.delete("1.0", tk.END)
        box.insert(tk.END, base64.b64encode(json.dumps(logs).encode()).decode())
    tk.Button(frame, text="Encrypt Logs", command=encrypt).pack()
    return frame

# =====================================================
# PAGE 3 – EVIDENCE REVIEW & BASELINE HASHES
# =====================================================
def page_hashes():
    frame = tk.Frame(container, bg=BG)
    tk.Label(frame, text="3. Evidence Review & Baseline Hashes",
             fg=TEXT, bg=BG, font=("Segoe UI", 18, "bold")).pack(anchor="w")

    box = tk.Text(frame, bg=CARD, fg=TEXT, font=("Consolas", 10))
    box.pack(fill="both", expand=True)

    def show():
        box.config(state="normal")
        box.delete("1.0", tk.END)
        if not logs:
            box.insert(tk.END, "No evidence available.")
            return
        box.insert(tk.END, "SEALED EVIDENCE LOGS\n")
        box.insert(tk.END, "-"*60 + "\n")
        box.insert(tk.END, json.dumps(logs, indent=2))
        box.insert(tk.END, "\n\nBASELINE HASHES\n")
        box.insert(tk.END, "-"*60 + "\n")
        box.insert(tk.END, f"MD5    : {baseline_md5}\n")
        box.insert(tk.END, f"SHA256 : {baseline_sha256}\n")
        box.config(state="disabled")

    tk.Button(frame, text="View Evidence & Hashes", command=show).pack(pady=5)
    return frame

# =====================================================
# PAGE 4 – INTEGRITY
# =====================================================
def page_integrity():
    frame = tk.Frame(container, bg=BG)
    tk.Label(frame, text="4. Evidence Integrity Verification",
             fg=TEXT, bg=BG, font=("Segoe UI", 18, "bold")).pack(anchor="w")

    verdict = tk.Label(frame, text="NOT VERIFIED", fg=FAIL, bg=BG,
                       font=("Segoe UI", 12, "bold"))
    verdict.pack()

    box = tk.Text(frame, bg=CARD, fg=TEXT)
    box.pack(fill="both", expand=True)

    def verify():
        global verify_md5, verify_sha256, integrity_status
        verify_md5, verify_sha256 = compute_hash_from_file(sealed_log_file)
        integrity_status = "VERIFIED" if (
            verify_md5 == baseline_md5 and verify_sha256 == baseline_sha256
        ) else "FAILED"
        verdict.config(text=integrity_status, fg=OK if integrity_status=="VERIFIED" else FAIL)
        box.delete("1.0", tk.END)
        box.insert(tk.END,
            f"BASELINE HASHES\nMD5: {baseline_md5}\nSHA256: {baseline_sha256}\n\n"
            f"VERIFICATION HASHES\nMD5: {verify_md5}\nSHA256: {verify_sha256}\n\n"
            f"STATUS: {integrity_status}"
        )

    tk.Button(frame, text="Verify Integrity", command=verify).pack()
    return frame

# =====================================================
# PAGE 5 – RECONSTRUCTION
# =====================================================
def page_reconstruction():
    frame = tk.Frame(container, bg=BG)
    tk.Label(frame, text="5. Event Reconstruction",
             fg=TEXT, bg=BG, font=("Segoe UI", 18, "bold")).pack(anchor="w")
    box = tk.Text(frame, bg=CARD, fg=TEXT)
    box.pack(fill="both", expand=True)

    def reconstruct():
        global reconstruction_result
        reconstruction_result = ""
        box.delete("1.0", tk.END)
        for e in sorted(logs, key=lambda x: x["timestamp"]):
            reconstruction_result += (
                f"{time.ctime(e['timestamp'])} → {e['source']} : {e['value']}\n"
            )
        box.insert(tk.END, reconstruction_result)

    tk.Button(frame, text="Reconstruct Events", command=reconstruct).pack()
    return frame

# =====================================================
# PAGE 6 – REPORT
# =====================================================
def page_report():
    frame = tk.Frame(container, bg=BG)
    tk.Label(frame, text="6. Forensic Report",
             fg=TEXT, bg=BG, font=("Segoe UI", 18, "bold")).pack(anchor="w")

    tk.Label(frame, text="Case ID", fg=TEXT, bg=BG).pack(anchor="w")
    case_entry = tk.Entry(frame)
    case_entry.pack(anchor="w")

    tk.Label(frame, text="Investigator Name", fg=TEXT, bg=BG).pack(anchor="w")
    investigator_entry = tk.Entry(frame)
    investigator_entry.pack(anchor="w")

    def generate_report():
        if integrity_status != "VERIFIED":
            messagebox.showerror("Error", "Integrity not verified")
            return

        folder = filedialog.askdirectory()
        if not folder:
            return

        filename = f"IFED_Report_{case_entry.get()}_{time.strftime('%Y%m%d_%H%M%S')}_{serial_number}.pdf"
        path = os.path.join(folder, filename)

        c = canvas.Canvas(path, pagesize=A4)
        width, height = A4
        page_no = 1

        HEADER_HEIGHT = 170
        BOTTOM_MARGIN = 60
        LEFT = 40
        RIGHT = 40

        def header():
            c.setFont("Helvetica-Bold", 10)
            c.setFillColor(HexColor("#1f4fd8"))
            c.drawString(LEFT, height - 30, f"{TOOL_NAME} | Version {VERSION}")
            c.setFillColor(black)
            c.setFont("Helvetica-Bold", 12)
            c.drawString(LEFT, height - 55, "FORENSIC REPORT")
            c.line(LEFT, height - 60, width - RIGHT, height - 60)
            c.setFont("Helvetica", 9)
            c.drawString(LEFT, height - 80, f"Case ID: {case_entry.get()}")
            c.drawString(LEFT, height - 95, f"Investigator: {investigator_entry.get()}")
            c.drawString(LEFT, height - 110, f"Serial: {serial_number}")
            c.drawString(LEFT, height - 125, f"Log Source: {imported_log_source}")
            c.drawString(LEFT, height - 140, f"Generated: {time.ctime()}")
            c.setFont("Helvetica", 8)
            c.drawString(LEFT, 30, f"Page {page_no}")

        def start_page():
            header()
            t = c.beginText(LEFT, height - HEADER_HEIGHT)
            t.setFont("Helvetica", 10)
            return t

        text = start_page()

        def add(line=""):
            nonlocal page_no, text
            if text.getY() < BOTTOM_MARGIN:
                c.drawText(text)
                c.showPage()
                page_no += 1
                text = start_page()
            text.textLine(line)

        add("1. Evidence Acquisition")
        add("-"*60)
        for l in json.dumps(logs, indent=2).split("\n"):
            add(l)

        add("")
        add("2. Cryptographic Hashes")
        add("-"*60)
        add(f"Baseline MD5: {baseline_md5}")
        add(f"Baseline SHA256: {baseline_sha256}")
        add(f"Verification MD5: {verify_md5}")
        add(f"Verification SHA256: {verify_sha256}")

        add("")
        add("3. Evidence Integrity Verdict")
        add("-"*60)
        add(f"Evidence integrity {integrity_status}.")

        add("")
        add("4. Event Reconstruction")
        add("-"*60)
        for l in reconstruction_result.split("\n"):
            add(l)

        add("")
        add("5. Legal Disclaimer")
        add("-"*60)
        add("This report is generated for academic and forensic analysis purposes.")
        add("IFED does not modify original evidence.")
        add("Final interpretation rests with the investigator.")

        c.drawText(text)
        c.showPage()
        c.save()

        messagebox.showinfo("Report Generated", filename)

    tk.Button(frame, text="Generate PDF Report",
              command=generate_report).pack(pady=20)

    return frame

# =====================================================
# REGISTER PAGES
# =====================================================
pages["1"] = page_acquisition()
pages["2"] = page_encryption()
pages["3"] = page_hashes()
pages["4"] = page_integrity()
pages["5"] = page_reconstruction()
pages["6"] = page_report()

nav_btn("1. Acquisition", "1")
nav_btn("2. Encryption", "2")
nav_btn("3. Review & Hashes", "3")
nav_btn("4. Integrity", "4")
nav_btn("5. Reconstruction", "5")
nav_btn("6. Report", "6")

highlight("1")
show_page("1")
root.mainloop()
