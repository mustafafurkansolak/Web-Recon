#!/usr/bin/env python3
# Sadece izinli sistemlerde kullan!

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import subprocess
import socket
import json
import urllib.request
import urllib.error
import re
import sys
import os
import time
import random
import webbrowser
from datetime import datetime

# ──────────────────────────────────────────────────────────────
#  RENK & FONT 
# ──────────────────────────────────────────────────────────────
C = {
    "bg"       : "#0a0a0a",
    "panel"    : "#111111",
    "border"   : "#1f1f1f",
    "border2"  : "#2a2a2a",
    "lime"     : "#aaff00",
    "lime_d"   : "#77bb00",
    "lime_dd"  : "#334400",
    "amber"    : "#ffcc00",
    "amber_d"  : "#aa8800",
    "red"      : "#ff2222",
    "red_d"    : "#991111",
    "blue"     : "#44aaff",
    "blue_d"   : "#2266aa",
    "white"    : "#dddddd",
    "grey"     : "#555555",
    "grey2"    : "#333333",
    "grey3"    : "#222222",
    "dim"      : "#3a3a3a",
    "button_fg": "#ffffff",
    "button_bg": "#222222",    
    "combo_fg" : "black",      
    "combo_bg" : "#111111",      
    "link_fg"  : "#44aaff",      
}

F  = ("Courier New", 10)
FB = ("Courier New", 10, "bold")
FS = ("Courier New", 9)
FT = ("Courier New", 13, "bold")
FX = ("Courier New", 8)

# ──────────────────────────────────────────────────────────────
#  ARAÇ KONTROLÜ
# ──────────────────────────────────────────────────────────────
def check_tool(n):
    try:
        return subprocess.run(["which", n], capture_output=True, timeout=5).returncode == 0
    except:
        return False

TOOLS = {k: check_tool(k) for k in ("nmap","subfinder","whatweb","dig","whois","curl","nuclei")}

# ──────────────────────────────────────────────────────────────
#  MODÜLLER 
# ──────────────────────────────────────────────────────────────
def run_whois(target, cb, speed="slow"):
    cb("[whois] sorgu başlatılıyor...\n","info")
    if not TOOLS["whois"]:
        cb("[whois] kurulu degil  →  sudo apt install whois\n","err"); return
    try:
        timeout = 10 if speed == "fast" else 30
        r = subprocess.run(["whois", target], capture_output=True, text=True, timeout=timeout)
        keys = ["registrar","creation date","updated date","expiry date",
                "name server","registrant","tech","admin","org","country",
                "registrar url","domain name"]
        found = [l.strip() for l in r.stdout.splitlines()
                 if any(k in l.lower() for k in keys) and ":" in l]
        if found:
            for f in found: cb(f"  {f}\n","ok")
        else:
            limit = 10 if speed == "fast" else 30
            cb(f"[whois] ham cikti (ilk {limit} satir):\n","warn")
            for l in r.stdout.splitlines()[:limit]: cb(f"  {l}\n","plain")
        cb("[whois] bitti.\n\n","ok")
    except subprocess.TimeoutExpired:
        cb("[whois] zaman asimi!\n","warn")
    except Exception as e:
        cb(f"[whois] hata: {e}\n","err")

def run_dns(target, cb, speed="slow"):
    cb("[dns] kayitlar sorgulanıyor...\n","info")
    record_types = ["A","MX"] if speed == "fast" else ["A","AAAA","MX","NS","TXT","CNAME","SOA"]
    for rtype in record_types:
        if TOOLS["dig"]:
            try:
                r = subprocess.run(["dig","+short",rtype,target],
                                   capture_output=True, text=True, timeout=5 if speed=="fast" else 10)
                out = r.stdout.strip()
                cb(f"  {rtype:<6} {out if out else '(yok)'}\n","ok" if out else "dim")
            except Exception as e:
                cb(f"  {rtype:<6} hata: {e}\n","warn")
        else:
            if rtype == "A":
                cb("[dns] dig yok, socket ile cozumleniyor...\n","warn")
                try:
                    ip = socket.gethostbyname(target)
                    cb(f"  A      {ip}\n","ok")
                    if speed != "fast":
                        try:
                            h = socket.gethostbyaddr(ip)
                            cb(f"  PTR    {h[0]}\n","ok")
                        except: pass
                except Exception as e:
                    cb(f"  A      cozumlenemedi: {e}\n","err")
            break
    cb("[dns] bitti.\n\n","ok")

def run_ip_info(target, cb, speed="slow"):
    cb("[ip-info] cografi konum alınıyor...\n","info")
    try:
        try: ip = socket.gethostbyname(target)
        except: ip = target
        cb(f"  hedef ip  : {ip}\n","ok")
        fields = "status,country,city,isp" if speed == "fast" else "status,country,regionName,city,isp,org,as"
        url = f"http://ip-api.com/json/{ip}?fields={fields}"
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5 if speed=="fast" else 10) as resp:
            d = json.loads(resp.read().decode())
        if d.get("status") == "success":
            mapping = [("ulke","country")] + ([("bolge","regionName")] if speed!="fast" else []) + \
                      [("sehir","city"),("isp","isp")] + \
                      ([("org","org"),("as","as")] if speed!="fast" else [])
            for label,key in mapping:
                cb(f"  {label:<10}: {d.get(key,'?')}\n","ok")
        else:
            cb("  konum bilgisi alinamadi.\n","warn")
    except Exception as e:
        cb(f"  hata: {e}\n","warn")
    cb("[ip-info] bitti.\n\n","ok")

def run_subdomains(target, cb, speed="slow"):
    cb("[subdomain] alt alan adlari aranıyor...\n","info")
    found = set()
    if speed == "fast":
        cb("  hizli mod → sadece crt.sh taranıyor...\n","info")
    else:
        if TOOLS["subfinder"]:
            cb("  subfinder calıstırılıyor...\n","info")
            try:
                r = subprocess.run(["subfinder","-d",target,"-silent","-timeout","30"],
                                   capture_output=True, text=True, timeout=60)
                for line in r.stdout.splitlines():
                    s = line.strip()
                    if s:
                        found.add(s)
                        # IP adresini al
                        try:
                            ip = socket.gethostbyname(s)
                            cb(f"  [+] {s} -> {ip}\n","ok")
                        except:
                            cb(f"  [+] {s} -> (IP alınamadı)\n","ok")
            except subprocess.TimeoutExpired:
                cb("  subfinder zaman asimi!\n","warn")
            except Exception as e:
                cb(f"  subfinder hata: {e}\n","warn")
        else:
            cb("  subfinder yok → crt.sh kullanılıyor...\n","warn")

    cb("  crt.sh sertifika loglari taranıyor...\n","info")
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15 if speed=="fast" else 30) as resp:
            data = json.loads(resp.read().decode())
        for entry in data:
            for sub in entry.get("name_value","").splitlines():
                sub = sub.strip().lstrip("*.")
                if target in sub and sub not in found:
                    found.add(sub)
                    # IP adresini al
                    try:
                        ip = socket.gethostbyname(sub)
                        cb(f"  [+] {sub} -> {ip}\n","ok")
                    except:
                        cb(f"  [+] {sub} -> (IP alınamadı)\n","ok")
    except Exception as e:
        cb(f"  crt.sh hata: {e}\n","warn")

    if speed != "fast":
        common = ["www","mail","ftp","admin","vpn","dev","api",
                  "test","staging","m","blog","shop","app","portal"]
        cb("  dns brute yaygın subdomainler deneniyor...\n","info")
        for s in common:
            full = f"{s}.{target}"
            if full not in found:
                try:
                    ip = socket.gethostbyname(full)
                    found.add(full)
                    cb(f"  [+] {full} -> {ip}  (brute)\n","ok")
                except socket.gaierror:
                    pass  

    cb(f"  toplam: {len(found)} subdomain\n" if found else "  bulunamadi.\n",
       "ok" if found else "dim")
    cb("[subdomain] bitti.\n\n","ok")

def run_port_scan(target, cb, speed="slow"):
    cb("[port-scan] baslatılıyor...\n","info")
    if speed == "fast":
        ports = [21,22,23,80,443,3306,8080]
        port_str = "21,22,23,80,443,3306,8080"
    else:
        ports = [21,22,23,25,53,80,110,143,443,465,587,993,995,3306,3389,5432,6379,8080,8443,8888]
        port_str = "21,22,23,25,53,80,110,143,443,465,587,993,995,3306,3389,5432,6379,8080,8443,8888"

    if not TOOLS["nmap"] or speed == "fast":
        cb("  socket ile hızlı tarama yapılıyor...\n","info")
        try: ip = socket.gethostbyname(target)
        except: ip = target
        open_p = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5 if speed=="fast" else 1)
                if s.connect_ex((ip, port)) == 0:
                    open_p.append(port)
                    try: svc = socket.getservbyport(port)
                    except: svc = "?"
                    cb(f"  ACIK  {port:<6}  {svc}\n","ok")
                s.close()
            except: pass
        if not open_p: cb("  acık port bulunamadi.\n","dim")
        cb("[port-scan] bitti.\n\n","ok"); return

    cb("  nmap -sV -T2 --script=banner calistiriliyor...\n","info")
    try:
        r = subprocess.run(
            ["nmap","-sV","--open","-T2","-p", port_str, "--script=banner", target],
            capture_output=True, text=True, timeout=120)
        in_p = False; open_p = []
        for line in r.stdout.splitlines():
            if "PORT" in line and "STATE" in line: in_p = True; continue
            if in_p:
                if not line.strip() or line.startswith("Service") or "Nmap done" in line:
                    in_p = False; continue
                if "/tcp" in line or "/udp" in line:
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "open":
                        pp = parts[0]; svc = parts[2] if len(parts)>2 else "?"
                        ver = " ".join(parts[3:]) if len(parts)>3 else ""
                        open_p.append(pp)
                        cb(f"  ACIK  {pp:<14}  {svc:<14}  {ver}\n","ok")
            if "| banner:" in line.lower():
                cb(f"         banner: {line.split('banner:')[-1].strip()}\n","info")
        if not open_p: cb("  acık port yok.\n","dim")
    except subprocess.TimeoutExpired:
        cb("  zaman asimi (120s)\n","warn")
    except Exception as e:
        cb(f"  hata: {e}\n","err")
    cb("[port-scan] bitti.\n\n","ok")

def _manual_headers(target, cb):
    try:
        url = target if target.startswith("http") else f"http://{target}"
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            hdrs = dict(resp.headers); status = resp.status
        cb(f"  http status    : {status}\n","ok")
        keys = ["server","x-powered-by","x-generator","via","x-drupal",
                "x-wordpress","x-joomla","x-frame-options",
                "strict-transport-security","content-security-policy","set-cookie"]
        for k,v in hdrs.items():
            if k.lower() in keys: cb(f"  {k}: {v}\n","ok")
    except Exception as e:
        cb(f"  header alinamadi: {e}\n","warn")

def run_whatweb(target, cb, speed="slow"):
    cb("[web-tech] tespit ediliyor...\n","info")
    if speed == "fast" or not TOOLS["whatweb"]:
        if speed != "fast" and not TOOLS["whatweb"]:
            cb("  whatweb yok → http header ile devam...\n","warn")
        _manual_headers(target, cb)
    else:
        try:
            url = target if target.startswith("http") else f"http://{target}"
            aggression = "3" if speed == "slow" else "1"
            r = subprocess.run(["whatweb","--color=never","-a",aggression,url],
                               capture_output=True, text=True, timeout=30 if speed=="slow" else 15)
            out = r.stdout.strip()
            if out:
                for line in out.splitlines(): cb(f"  {line}\n","ok")
            else:
                _manual_headers(target, cb)
        except subprocess.TimeoutExpired:
            cb("  zaman asimi!\n","warn")
        except Exception as e:
            cb(f"  hata: {e}\n","err"); _manual_headers(target, cb)
    cb("[web-tech] bitti.\n\n","ok")

def run_vuln_check(target, cb, speed="slow"):
    
    cb("[vuln] tarama baslatılıyor...\n","info")
    
    # Nmap vuln taraması
    if TOOLS["nmap"]:
        if speed == "fast":
            ports = "80,443,8080,8443,21,22,3306,3389"
            scripts = "vulners,http-methods,ftp-anon"
            timeout = 90
            cb("  [nmap] hizli mod: yaygin portlar taranıyor (vulners dahil)\n","info")
        else:
            ports = "21,22,23,25,80,110,143,443,465,587,993,995,3306,3389,5432,6379,8080,8443,8888"
            scripts = "vulners,http-methods,http-headers,ssh-auth-methods,ftp-anon,smtp-open-relay"
            timeout = 180
            cb("  [nmap] yavas mod: detayli tarama yapılıyor...\n","info")

        try:
            r = subprocess.run(
                ["nmap","-sV","--open","-T2","-p", ports, f"--script={scripts}", target],
                capture_output=True, text=True, timeout=timeout)
            found = False
            for line in r.stdout.splitlines():
                # CVE kontrolü 
                if "|" in line and ("VULNERABLE" in line.upper() or "CVE-" in line.upper()):
                    cve_match = re.search(r'(CVE-\d{4}-\d+)', line, re.IGNORECASE)
                    if cve_match:
                        cve_id = cve_match.group(1).upper()
                        url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
                        cb(f"  [nmap] {line.strip()}\n", {'tag': 'err', 'url': url})
                    else:
                        cb(f"  [nmap] {line.strip()}\n","err")
                    found = True
                # CWE kontrolü
                elif "|" in line and "CWE-" in line.upper():
                    cwe_match = re.search(r'(CWE-\d+)', line, re.IGNORECASE)
                    if cwe_match:
                        cwe_id = cwe_match.group(1).upper()
                        cwe_num = cwe_id.split('-')[1]
                        url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                        cb(f"  [nmap] {line.strip()}\n", {'tag': 'warn', 'url': url})
                    else:
                        cb(f"  [nmap] {line.strip()}\n","warn")
                    found = True
                elif "|" in line and any(kw in line.lower() for kw in ["critical","high","medium","risk"]):
                    cb(f"  [nmap] {line.strip()}\n","warn"); found = True
                elif line.strip().startswith("|"):
                    if "ftp-anon" in line.lower() and "anonymous" in line.lower():
                        cb("  [nmap] [!!!] Anonymous FTP acik!\n","err"); found = True
                    elif "smtp-open-relay" in line.lower() and "enabled" in line.lower():
                        cb("  [nmap] [!!!] SMTP Open Relay!\n","err"); found = True
            if not found:
                cb("  [nmap] kritik zafiyet bulunamadi.\n","dim")
        except subprocess.TimeoutExpired:
            cb(f"  [nmap] zaman asimi ({timeout}s)\n","warn")
        except Exception as e:
            cb(f"  [nmap] hata: {e}\n","err")
    else:
        cb("  [nmap] kurulu degil, atlaniyor.\n","warn")

    # Nuclei taraması
    if TOOLS["nuclei"]:
        cb("  [nuclei] tarama başlatılıyor...\n","info")
        # Hedef URL olmalı
        if not target.startswith(('http://','https://')):
            url = f"http://{target}"
        else:
            url = target

        if speed == "fast":
            cmd = [
                "nuclei", "-u", url,
                "-severity", "critical,high",
                "-rate-limit", "50",
                "-bulk-size", "25",
                "-timeout", "5",
                "-silent"
            ]
            timeout = 120
            cb("  [nuclei] hizli mod: kritik/yüksek önemli templateler taranıyor\n","info")
        else:
            cmd = [
                "nuclei", "-u", url,
                "-severity", "critical,high,medium,low",
                "-rate-limit", "150",
                "-bulk-size", "50",
                "-timeout", "10",
                "-silent"
            ]
            timeout = 300
            cb("  [nuclei] yavas mod: tum templateler taranıyor (bu biraz uzun sürebilir)\n","info")

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = r.stdout.strip()
            if output:
                for line in output.splitlines():
                    # CVE kontrolü
                    cve_match = re.search(r'(CVE-\d{4}-\d+)', line, re.IGNORECASE)
                    if cve_match:
                        cve_id = cve_match.group(1).upper()
                        url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
                        tag = 'err' if 'critical' in line.lower() or 'high' in line.lower() else 'warn'
                        cb(f"  [nuclei] {line}\n", {'tag': tag, 'url': url})
                    # CWE kontrolü
                    elif re.search(r'CWE-\d+', line, re.IGNORECASE):
                        cwe_match = re.search(r'(CWE-\d+)', line, re.IGNORECASE)
                        if cwe_match:
                            cwe_id = cwe_match.group(1).upper()
                            cwe_num = cwe_id.split('-')[1]
                            url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                            tag = 'err' if 'critical' in line.lower() or 'high' in line.lower() else 'warn'
                            cb(f"  [nuclei] {line}\n", {'tag': tag, 'url': url})
                    else:
                        tag = 'err' if 'critical' in line.lower() or 'high' in line.lower() else 'warn'
                        cb(f"  [nuclei] {line}\n", tag)
            else:
                cb("  [nuclei] herhangi bir zafiyet bulunamadi.\n","dim")
        except subprocess.TimeoutExpired:
            cb(f"  [nuclei] zaman asimi ({timeout}s)\n","warn")
        except Exception as e:
            cb(f"  [nuclei] hata: {e}\n","err")
    else:
        cb("  [nuclei] kurulu degil, atlaniyor.\n","warn")

    cb("[vuln] bitti.\n\n","ok")

# ──────────────────────────────────────────────────────────────
#  ÖZEL WİDGET'LAR
# ──────────────────────────────────────────────────────────────

class TermButton(tk.Frame):
    
    def __init__(self, parent, text, command,
                 fg=None, active_fg=None, active_bg=None,
                 width=None, state="normal", **kw):
        super().__init__(parent, bg=C["panel"], **kw)
        self._cmd     = command
        self._state   = state
        self._fg      = fg or C["lime"]
        self._afg     = active_fg or C["bg"]
        self._abg     = active_bg or (fg or C["lime"])
        self._normal_bg = C["panel"]

        self._lbl = tk.Label(
            self, text=f"  {text}  ",
            font=FB,
            fg=self._fg if state=="normal" else C["grey"],
            bg=C["panel"],
            cursor="hand2" if state=="normal" else "arrow",
            pady=5,
        )
        if width: self._lbl.config(width=width)
        self._lbl.pack(fill="x")

        self._bar = tk.Frame(self, bg=self._fg if state=="normal" else C["grey2"], height=1)
        self._bar.pack(fill="x")

        if state == "normal":
            self._lbl.bind("<Enter>", self._on_enter)
            self._lbl.bind("<Leave>", self._on_leave)
            self._lbl.bind("<Button-1>", self._on_click)

    def _on_enter(self, _=None):
        if self._state == "normal":
            self._lbl.config(bg=self._abg, fg=self._afg)
            self._bar.config(bg=self._abg)

    def _on_leave(self, _=None):
        self._lbl.config(bg=C["panel"], fg=self._fg)
        self._bar.config(bg=self._fg)

    def _on_click(self, _=None):
        if self._state == "normal" and self._cmd:
            self._cmd()

    def set_state(self, state):
        self._state = state
        if state == "disabled":
            self._lbl.config(fg=C["grey"], cursor="arrow", bg=C["panel"])
            self._bar.config(bg=C["grey2"])
        else:
            self._lbl.config(fg=self._fg, cursor="hand2")
            self._bar.config(bg=self._fg)
            self._lbl.bind("<Enter>", self._on_enter)
            self._lbl.bind("<Leave>", self._on_leave)
            self._lbl.bind("<Button-1>", self._on_click)


class ModuleToggle(tk.Frame):
    
    def __init__(self, parent, key, label, hint, var):
        super().__init__(parent, bg=C["panel"])
        self._var = var  # StringVar: "off", "slow", "fast"
        self._key = key

        # Combobox - okunabilirlik için renkler güncellendi
        self._combo = ttk.Combobox(
            self,
            values=["Kapalı", "Yavaş", "Hızlı"],
            state="readonly",
            width=8,
            font=FB,  # daha kalın font
        )
        self._combo.pack(side="right", padx=(0,4))
        self._combo.bind("<<ComboboxSelected>>", self._on_change)

        # Modül adı
        text_frame = tk.Frame(self, bg=C["panel"])
        text_frame.pack(side="left", fill="x", expand=True)
        tk.Label(text_frame, text=f"{label:<14}", font=FB,
                 fg=C["button_fg"], bg=C["panel"]).pack(side="left")

        self._refresh()

    def _refresh(self):
        val = self._var.get()
        if val == "off":
            self._combo.set("Kapalı")
        elif val == "slow":
            self._combo.set("Yavaş")
        elif val == "fast":
            self._combo.set("Hızlı")
        else:
            self._combo.set("Kapalı")
            self._var.set("off")

    def _on_change(self, event=None):
        selected = self._combo.get()
        if selected == "Kapalı":
            self._var.set("off")
        elif selected == "Yavaş":
            self._var.set("slow")
        elif selected == "Hızlı":
            self._var.set("fast")


# ──────────────────────────────────────────────────────────────
#  ANA UYGULAMA
# ──────────────────────────────────────────────────────────────

class ReconApp:
    def __init__(self, root):
        self.root      = root
        self.root.title("WEB Passive Reconnaissance")
        self.root.geometry("1180x800")
        self.root.minsize(960, 640)
        self.root.configure(bg=C["bg"])

        self.scanning   = False
        self.scan_thread = None
        self._scan_n    = 0
        self._ticker_id = None

        self._build()
        self._refresh_tool_status()
        

    # ── Layout ────────────────────────────────────────────────
    def _build(self):
        self._topbar()
        body = tk.Frame(self.root, bg=C["bg"])
        body.pack(fill="both", expand=True)

        left = tk.Frame(body, bg=C["panel"], width=270)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        self._left_panel(left)

        tk.Frame(body, bg=C["border2"], width=1).pack(side="left", fill="y")

        right = tk.Frame(body, bg=C["bg"])
        right.pack(side="left", fill="both", expand=True)
        self._console(right)

        self._statusbar()

    def _topbar(self):
        bar = tk.Frame(self.root, bg=C["bg"], height=44)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        tk.Label(bar, text="//", font=("Courier New",16,"bold"),
                 fg=C["lime_d"], bg=C["bg"]).pack(side="left", padx=(14,2), pady=8)
        tk.Label(bar, text="WEB-Recon", font=("Courier New",16,"bold"),
                 fg=C["lime"], bg=C["bg"]).pack(side="left", pady=8)
        tk.Label(bar, text="  v1.0",
                 font=FX, fg=C["grey"], bg=C["bg"]).pack(side="left", pady=12)

        self._clock_var = tk.StringVar()
        tk.Label(bar, textvariable=self._clock_var,
                 font=("Courier New",11,"bold"),
                 fg=C["grey"], bg=C["bg"]).pack(side="right", padx=14)
        self._tick_clock()

        tk.Frame(self.root, bg=C["lime_dd"], height=1).pack(fill="x")

    def _left_panel(self, parent):
        # Hedef girişi
        tk.Label(parent, text="TARGET", font=FB,
                 fg=C["lime"], bg=C["panel"]).pack(anchor="w", padx=12, pady=(14,2))

        inp_frame = tk.Frame(parent, bg=C["border2"], pady=1, padx=1)
        inp_frame.pack(fill="x", padx=12)

        self._target_var = tk.StringVar()
        self._entry = tk.Entry(
            inp_frame,
            textvariable=self._target_var,
            font=("Courier New",11),
            bg=C["bg"],
            fg=C["amber"],
            insertbackground=C["amber"],
            selectbackground=C["border2"],
            selectforeground=C["white"],
            relief="flat", bd=6,
        )
        self._entry.pack(fill="x")
        self._entry.insert(0, "hedef: domain.com veya IP")
        self._entry.bind("<FocusIn>",  self._entry_focus_in)
        self._entry.bind("<FocusOut>", self._entry_focus_out)
        self._entry.bind("<Return>",   lambda e: self._start())

        tk.Label(parent, text="  ipv4, ipv6 veya domain",
                 font=FX, fg=C["grey"], bg=C["panel"]).pack(anchor="w", padx=12)

        self._sep(parent)

        # Modüller
        tk.Label(parent, text="MODULES (sağdan hız seçin)", font=FB,
                 fg=C["lime"], bg=C["panel"]).pack(anchor="w", padx=12, pady=(0,4))
        tk.Label(parent, text="  Kapalı | Yavaş | Hızlı",
                 font=FX, fg=C["grey"], bg=C["panel"]).pack(anchor="w", padx=12, pady=(0,6))

        self._modules = {}
        self._toggle_widgets = []
        defs = [
            ("whois",     "WHOIS",       "kayit bilgisi"),
            ("dns",       "DNS",         "kayit sorgula"),
            ("ipinfo",    "IP-INFO",     "konum / isp"),
            ("subdomain", "SUBDOMAIN",   "alt alanlar"),
            ("ports",     "PORT-SCAN",   "acık portlar"),
            ("webtech",   "WEB-TECH",    "cms / server"),
            ("vuln",      "VULN",        "zafiyet (nmap+nuclei)"),
        ]
        mod_wrap = tk.Frame(parent, bg=C["panel"])
        mod_wrap.pack(fill="x", padx=10, pady=(0,6))
        for key, label, hint in defs:
            var = tk.StringVar(value="slow")
            self._modules[key] = var
            w = ModuleToggle(mod_wrap, key, label, hint, var)
            w.pack(fill="x", pady=1)
            self._toggle_widgets.append(w)

        self._sep(parent)

        # Kısayollar
        shortcut_row = tk.Frame(parent, bg=C["panel"])
        shortcut_row.pack(fill="x", padx=10, pady=(0,4))
        tk.Label(shortcut_row, text="hızlı seçim:", font=FX,
                 fg=C["grey"], bg=C["panel"]).pack(side="left", padx=(2,6))

        def set_all(value):
            for var in self._modules.values():
                var.set(value)
            for w in self._toggle_widgets:
                w._refresh()

        tk.Label(shortcut_row, text="[tümü yavaş]", font=FX,
                 fg=C["blue"], bg=C["panel"], cursor="hand2").pack(side="left", padx=3)
        shortcut_row.winfo_children()[-1].bind("<Button-1>", lambda e: set_all("slow"))

        tk.Label(shortcut_row, text="[tümü hızlı]", font=FX,
                 fg=C["blue"], bg=C["panel"], cursor="hand2").pack(side="left", padx=3)
        shortcut_row.winfo_children()[-1].bind("<Button-1>", lambda e: set_all("fast"))

        tk.Label(shortcut_row, text="[tümü kapalı]", font=FX,
                 fg=C["blue"], bg=C["panel"], cursor="hand2").pack(side="left", padx=3)
        shortcut_row.winfo_children()[-1].bind("<Button-1>", lambda e: set_all("off"))

        self._sep(parent)

        # Butonlar
        btn_wrap = tk.Frame(parent, bg=C["panel"])
        btn_wrap.pack(fill="x", padx=10, pady=(0,6))

        self._btn_start = TermButton(
            btn_wrap, "TARAMAYI BASLAT  [ENTER]",
            self._start,
            fg=C["lime"], active_fg=C["bg"], active_bg=C["lime"])
        self._btn_start.pack(fill="x", pady=(0,4))

        self._btn_stop = TermButton(
            btn_wrap, "TARAMAYI DURDUR",
            self._stop,
            fg=C["red"], active_fg=C["white"], active_bg=C["red_d"],
            state="disabled")
        self._btn_stop.pack(fill="x", pady=(0,4))

        row2 = tk.Frame(btn_wrap, bg=C["panel"])
        row2.pack(fill="x")

        self._btn_clear = TermButton(
            row2, "TEMIZLE",
            self._clear,
            fg=C["grey"], active_fg=C["white"], active_bg=C["grey2"])
        self._btn_clear.pack(side="left", fill="x", expand=True, padx=(0,3))

        self._btn_save = TermButton(
            row2, "KAYDET",
            self._save,
            fg=C["grey"], active_fg=C["white"], active_bg=C["grey2"])
        self._btn_save.pack(side="left", fill="x", expand=True, padx=(3,0))

        self._sep(parent)

        # Araç durumu
        tk.Label(parent, text="TOOL STATUS", font=FB,
                 fg=C["lime"], bg=C["panel"]).pack(anchor="w", padx=12, pady=(0,4))

        self._tool_labels = {}
        tframe = tk.Frame(parent, bg=C["panel"])
        tframe.pack(fill="x", padx=12, pady=(0,8))
        for t in TOOLS:
            row = tk.Frame(tframe, bg=C["panel"])
            row.pack(fill="x", pady=1)
            tk.Label(row, text=f"  {t:<12}", font=FX,
                     fg=C["grey"], bg=C["panel"]).pack(side="left")
            lbl = tk.Label(row, font=FX, bg=C["panel"])
            lbl.pack(side="right", padx=4)
            self._tool_labels[t] = lbl

        self._sep(parent)

        # Github sayfası
        tk.Label(parent,
                 text="    GITHUB:\n    https://github.com/mustafafurkansolak\n    /Web-Recon.git",
                 font=FX, fg=C["amber_d"], bg=C["panel"],
                 justify="left").pack(anchor="w", padx=8, pady=(0,10))

    def _console(self, parent):
        hdr = tk.Frame(parent, bg=C["border"], height=26)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="  OUTPUT", font=FX,
                 fg=C["grey"], bg=C["border"]).pack(side="left", pady=4)

        for txt, clr in [("OK",C["lime"]),("INFO",C["blue"]),
                          ("WARN",C["amber"]),("ERR",C["red"])]:
            tk.Label(hdr, text=f"  {txt}", font=FX,
                     fg=clr, bg=C["border"]).pack(side="right", pady=4)

        tk.Frame(parent, bg=C["border2"], height=1).pack(fill="x")

        self._out = scrolledtext.ScrolledText(
            parent,
            font=("Courier New",10),
            bg=C["bg"],
            fg=C["white"],
            insertbackground=C["lime"],
            selectbackground=C["border2"],
            selectforeground=C["lime"],
            relief="flat", bd=0,
            padx=12, pady=8,
            wrap="word",
            state="disabled",
            spacing1=1, spacing3=1,
        )
        self._out.pack(fill="both", expand=True)

        tags = {
            "info"   : C["blue"],
            "ok"     : C["lime"],
            "warn"   : C["amber"],
            "err"    : C["red"],
            "dim"    : C["grey"],
            "plain"  : C["white"],
            "hdr"    : C["lime"],
            "success": C["lime"],
            "banner" : C["dim"],
        }
        for tag, color in tags.items():
            bold = tag in ("hdr","err","success")
            fnt  = ("Courier New",10,"bold") if bold else ("Courier New",10)
            self._out.tag_config(tag, foreground=color, font=fnt)
        
        # Link tag'i için ayrı konfigürasyon
        self._out.tag_config("link", foreground=C["link_fg"], underline=True, font=FB)
        self._out.tag_bind("link", "<Button-1>", self._open_link)
        self._out.tag_bind("link", "<Enter>", lambda e: self._out.config(cursor="hand2"))
        self._out.tag_bind("link", "<Leave>", lambda e: self._out.config(cursor=""))

    def _open_link(self, event):
        """Tıklanan linkin URL'sini al ve tarayıcıda aç"""
        index = self._out.index("@%s,%s" % (event.x, event.y))
        tags = self._out.tag_names(index)
        for tag in tags:
            if tag.startswith("link_"):
                url = tag[5:] 
                webbrowser.open(url)
                return

    def _write_link(self, text, url, original_tag="plain"):
        """Metni hem orijinal renk tag'i hem de link tag'i ile ekle"""
        self._out.config(state="normal")
        link_tag = f"link_{url}"
        self._out.insert(tk.END, text, (original_tag, link_tag, "link"))
        self._out.see(tk.END)
        self._out.config(state="disabled")

    def _statusbar(self):
        tk.Frame(self.root, bg=C["border2"], height=1).pack(fill="x", side="bottom")
        bar = tk.Frame(self.root, bg=C["border"], height=24)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._progress = ttk.Progressbar(
            bar, mode="indeterminate", length=100)
        self._progress.pack(side="left", padx=(8,0), pady=6)

        self._status_var = tk.StringVar(value="hazir  //  hedef gir ve enter'a bas")
        tk.Label(bar, textvariable=self._status_var,
                 font=FX, fg=C["grey"], bg=C["border"]).pack(side="left", padx=8)

        self._scan_lbl = tk.Label(bar, text="scan #000",
                                  font=FX, fg=C["grey2"], bg=C["border"])
        self._scan_lbl.pack(side="right", padx=10)

    # ── Yardımcı ──────────────────────────────────────────────
    def _sep(self, parent, color=None):
        tk.Frame(parent, bg=color or C["border2"], height=1).pack(
            fill="x", padx=8, pady=6)

    def _tick_clock(self):
        self._clock_var.set(datetime.now().strftime("%H:%M:%S"))
        self.root.after(1000, self._tick_clock)

    def _entry_focus_in(self, _=None):
        v = self._target_var.get()
        if "hedef" in v or "domain" in v:
            self._entry.delete(0, tk.END)
            self._entry.config(fg=C["amber"])

    def _entry_focus_out(self, _=None):
        if not self._target_var.get().strip():
            self._entry.insert(0, "hedef: domain.com veya IP")
            self._entry.config(fg=C["grey"])

    def _refresh_tool_status(self):
        for t, ok in TOOLS.items():
            lbl = self._tool_labels[t]
            lbl.config(text="ok" if ok else "--",
                       fg=C["lime_d"] if ok else C["red"])

    def _write(self, text, tag="plain"):
        self._out.config(state="normal")
        self._out.insert(tk.END, text, tag)
        self._out.see(tk.END)
        self._out.config(state="disabled")

    def _clear(self):
        self._out.config(state="normal")
        self._out.delete(1.0, tk.END)
        self._out.config(state="disabled")
        self._status_var.set("temizlendi.")

    def _save(self):
        content = self._out.get(1.0, tk.END)
        if not content.strip():
            messagebox.showinfo("bilgi","kaydedilecek rapor yok."); return
        tgt = self._target_var.get().strip().replace(".","_").replace("/","_")
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn  = f"recon_{tgt}_{ts}.txt"
        try:
            with open(fn,"w",encoding="utf-8") as f: f.write(content)
            messagebox.showinfo("kaydedildi", fn)
        except Exception as e:
            messagebox.showerror("hata", str(e))

    # ── Tarama ────────────────────────────────────────────────
    def _start(self):
        tgt = self._target_var.get().strip()
        if not tgt or "hedef" in tgt or "domain" in tgt:
            messagebox.showwarning("uyari","gecerli bir hedef girin."); return
        if self.scanning: return
        active = {key: var.get() for key, var in self._modules.items() if var.get() != "off"}
        if not active:
            messagebox.showwarning("uyari","en az bir modul secin."); return

        self._scan_n += 1
        self._scan_lbl.config(text=f"scan #{self._scan_n:03d}")
        self._clear()
        self.scanning = True
        self._btn_start.set_state("disabled")
        self._btn_stop.set_state("normal")
        self._progress.start(10)
        self._status_var.set(f"taranıyor: {tgt}")

        self.scan_thread = threading.Thread(
            target=self._run, args=(tgt, active), daemon=True)
        self.scan_thread.start()

    def _stop(self):
        self.scanning = False
        self._done()
        self._write("\n  [!] kullanici tarafinan durduruldu.\n\n","warn")

    def _done(self):
        self.scanning = False
        self._progress.stop()
        self._btn_start.set_state("normal")
        self._btn_stop.set_state("disabled")
        self._status_var.set("tamamlandi.")

    def _run(self, target, modules):
        def cb(text, tag="plain"):
            if not self.scanning: return
            if isinstance(tag, dict) and 'url' in tag:
                # Linkli mesaj
                url = tag['url']
                original_tag = tag.get('tag', 'plain')
                self.root.after(0, lambda t=text, u=url, ot=original_tag: self._write_link(t, u, ot))
            else:
                self.root.after(0, lambda t=text, tg=tag: self._write(t, tg))

        def st(text):
            self.root.after(0, lambda: self._status_var.set(text))

        ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        cb(f"{'─'*60}\n","dim")
        cb(f"  target   : {target}\n","hdr")
        cb(f"  date     : {ts}\n","dim")
        mod_list = [f"{k}({v})" for k,v in modules.items()]
        cb(f"  modules  : {', '.join(mod_list)}\n","dim")
        cb(f"{'─'*60}\n\n","dim")

        MAP = {
            "whois"    : (run_whois,      "whois"),
            "dns"      : (run_dns,        "dns"),
            "ipinfo"   : (run_ip_info,    "ip-info"),
            "subdomain": (run_subdomains, "subdomain"),
            "ports"    : (run_port_scan,  "port-scan"),
            "webtech"  : (run_whatweb,    "web-tech"),
            "vuln"     : (run_vuln_check, "vuln"),
        }

        for key in MAP:
            if not self.scanning: break
            if key not in modules: continue
            speed = modules[key]
            fn, label = MAP[key]
            st(f"// {label} ({speed}) calısıyor...")
            cb(f"── {label.upper()} ({speed.upper()}) {'─'*(50-len(label)-len(speed)-2)}\n","info")
            fn(target, cb, speed=speed)

        if self.scanning:
            cb(f"{'─'*60}\n","dim")
            cb("  tarama tamamlandi.\n","success")
            cb(f"{'─'*60}\n","dim")
            self.root.after(0, self._done)


# ──────────────────────────────────────────────────────────────
#  GIRIS NOKTASI
# ──────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TCombobox",
                    fieldbackground=C["combo_bg"],
                    background=C["combo_bg"],
                    foreground=C["combo_fg"],
                    arrowcolor=C["combo_fg"],
                    bordercolor=C["border2"],
                    lightcolor=C["border2"],
                    darkcolor=C["border2"])
    style.configure("TProgressbar",
                    troughcolor=C["border"],
                    background=C["lime_d"],
                    darkcolor=C["lime_d"])
    app = ReconApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
