#!/usr/bin/env python3
"""FLS_CheckR - scans a flash drive's structure and flags problems.

Read-only (never changes or deletes anything). Standard library only.
Run:  python FLS_CheckR.py
"""
import ctypes, functools, hashlib, heapq, os, platform, queue, re, shutil, string, subprocess, tempfile, threading, time
from collections import defaultdict
from dataclasses import dataclass, field
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog, font as tkfont

WIN, MAC = platform.system() == "Windows", platform.system() == "Darwin"
NO_WINDOW = 0x08000000  # Windows: start a child process without a console window

BG, PANEL, INK, MUTED, LINE = "#E6EBEF", "#F8FAFB", "#1B2530", "#66727F", "#CBD4DA"
ACCENT, ACCENT_D, GOOD, FREE = "#2C6E91", "#235A77", "#2E8B63", "#DCE3E8"
SEV = {"high": "#C5382E", "medium": "#D98A0B", "low": "#5B84AD", "info": "#8A96A1"}
ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
MAX_ITEMS = 300

# key: (severity, title, what it means, what to do)
RULES = {
    "autorun": ("high", "autorun.inf at drive root", "Windows can use this file to launch a program as soon as the drive is plugged in. It is a common malware route.", "Press Disable autorun.inf in the sidebar (it renames the file so it cannot run), then scan the drive with antivirus."),
    "shortcut_virus": ("high", "Shortcut-virus pattern", "Shortcut (.lnk) files share names with hidden folders. Your real folders were probably hidden and replaced by shortcuts.", "Scan with antivirus, then run  attrib -h -r -s /s /d X:\\*.*  (X = drive letter) and delete the .lnk files."),
    "double_ext": ("high", "Disguised programs (double extension)", "Names like photo.jpg.exe look like documents but run as programs.", "Do not open them. Delete them and scan the drive."),
    "hidden_exec": ("high", "Hidden programs at drive root", "Hidden executables at the top of a drive are a typical malware sign.", "Scan with antivirus before using this drive on another computer."),
    "read_error": ("high", "Files that fail to read", "The drive returned an I/O error. This usually means failing flash cells or a loose connection.", "Copy off everything else now, then use Run CHKDSK in the sidebar (Windows) or fsck (Linux/macOS), and replace the drive if errors return."),
    "unreadable": ("high", "Folders or entries that cannot be read", "The directory data could not be read, which can mean file-system damage.", "Press Rescue files in the sidebar to copy out everything that still reads. Only then try Run CHKDSK, because a repair can delete damaged entries. If files are missing, try PhotoRec or TestDisk."),
    "chkdsk_found": ("medium", "Fragments recovered by CHKDSK", "FOUND.000 folders and .chk files are pieces CHKDSK rescued after earlier corruption.", "Check them for anything you need, then delete them. If they keep coming back the drive is failing."),
    "root_exec": ("medium", "Program files at drive root", "Programs in the top folder of a data drive are unusual.", "Confirm you recognise each one."),
    "bad_name": ("medium", "Problematic names", "Trailing spaces or dots, reserved words (CON, NUL) or illegal characters can fail to copy or open on Windows.", "Rename them."),
    "long_path": ("medium", "Very long paths", "Paths near 260 characters break many Windows programs.", "Shorten folder names or move the folder closer to the root."),
    "zero_byte": ("low", "Empty (0 byte) files", "Often left behind by interrupted copies.", "Delete them if you do not need them."),
    "empty_dir": ("low", "Empty folders", "Folders with nothing inside.", "Delete them to tidy up."),
    "temp": ("low", "Leftover temporary files", "Unfinished downloads and editor leftovers.", "Delete them."),
    "deep": ("low", "Deeply nested folders", "More than 12 levels deep is hard to browse and risks path-length errors.", "Flatten the structure."),
    "big_dir": ("low", "Folders with over 5,000 entries", "These open slowly on FAT drives.", "Split them into subfolders."),
    "hidden_root": ("low", "Hidden items at drive root", "Normal for system folders, but this is also where shortcut viruses hide your files.", "Check that you recognise them."),
    "junk": ("info", "System clutter files", "Thumbs.db, .DS_Store and similar files are caches made by the operating system.", "Safe to delete."),
}
EXEC = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".pif", ".com"}
RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
DOUBLE = re.compile(r"\.(jpe?g|png|gif|docx?|xlsx?|pptx?|pdf|txt|mp3|mp4|avi|zip|rar)\.(exe|scr|bat|cmd|vbs|com|pif|js)$")
JUNK = {"thumbs.db", "desktop.ini", ".ds_store", "ehthumbs.db", ".trashes", ".spotlight-v100"}
SKIP = {"system volume information", "$recycle.bin", "lost+found", ".trash-1000"}
TEMP = {".tmp", ".crdownload", ".part", ".partial", ".temp"}
CATS = {
    "Documents": {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".odt", ".csv", ".rtf", ".md"},
    "Media": {".jpg", ".jpeg", ".png", ".gif", ".heic", ".webp", ".mp3", ".wav", ".flac", ".m4a", ".mp4", ".mkv", ".avi", ".mov"},
    "Archives": {".zip", ".rar", ".7z", ".iso", ".tar", ".gz", ".img"},
    "Programs": {".exe", ".dll", ".msi", ".apk", ".bat", ".cmd", ".app", ".dmg", ".sh"},
}
CAT_COL = {"Documents": "#2C6E91", "Media": "#7A5C9E", "Archives": "#8A9A5B", "Programs": "#B8604A", "Other": "#7D8A95", "Unscanned": "#B9C4CC", "Free": FREE}


SCRIPT_EXT = {".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".hta"}
SCRIPT_PATTERNS = (b"-encodedcommand", b"frombase64string", b"invoke-expression", b"downloadstring",
                   b"urldownloadtofile", b"attrib +h", b"attrib +s +h", b"currentversion\\run")
EICAR = b"EICAR-STANDARD-" + b"ANTIVIRUS-TEST-FILE"  # split so antivirus does not flag this source file
PENALTY = {"high": 14, "medium": 6, "low": 2, "info": 0}  # health-score points lost per finding


def fmt(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


@dataclass
class Finding:
    sev: str
    title: str
    count: int
    detail: str
    fix: str
    items: list = field(default_factory=list)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def admin_note(tool):
    return "" if is_admin() else f"{tool} needs administrator rights. Close FLS_CheckR and start it with Run as administrator.\n"


def find_defender():
    """Locate Microsoft Defender's command-line scanner (MpCmdRun.exe)."""
    plat = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows Defender", "Platform")
    cands = [os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")]
    try:
        cands = [os.path.join(plat, d, "MpCmdRun.exe") for d in sorted(os.listdir(plat), reverse=True)] + cands
    except OSError:
        pass
    return next((c for c in cands if os.path.isfile(c)), None)


# ---------------------------------------------------------------- scanning
class Scanner:
    """Walks a drive once and collects sizes, counts and problems. Read-only."""

    def __init__(s, root, fs, deep, q, stop):
        s.root, s.fs, s.deep, s.q, s.stop = root, fs, deep, q, stop
        s.counts, s.items = defaultdict(int), defaultdict(list)  # problem key -> count / first few paths
        s.info, s.order = {}, []                                  # per-folder totals, folders in visit order
        s.cat, s.largest = defaultdict(int), []                   # bytes per category, 10 biggest files (min-heap)
        s.files = s.dirs = s.bytes = s.maxd = 0
        s.last = 0.0

    def add(s, key, path):
        s.counts[key] += 1
        if len(s.items[key]) < MAX_ITEMS:
            s.items[key].append(path)

    def run(s):
        try:
            s.q.put(("done", s.scan()))
        except Exception as ex:
            s.q.put(("error", repr(ex)))

    @staticmethod
    def hidden(name, st):
        return bool(getattr(st, "st_file_attributes", 0) & 2) or (not WIN and name.startswith("."))

    def check_name(s, name, full):
        stem = name.split(".")[0].upper()
        if name != name.rstrip(" .") or stem in RESERVED or any(ord(c) < 32 or c in '<>:"|?*' for c in name) or len(name.encode("utf-8", "ignore")) > 255:
            s.add("bad_name", full)
        if len(full) >= 250:
            s.add("long_path", full)

    def read_test(s, path, size):
        """Read the start and end of a file; an I/O error means bad flash cells or a loose connection."""
        try:
            with open(path, "rb") as f:
                f.read(65536)
                if size > 131072:
                    f.seek(-4096, 2)
                    f.read(4096)
        except PermissionError:
            pass
        except OSError:
            s.add("read_error", path)

    def scan(s):
        t0 = time.time()
        s.walk()
        s.roll_up()
        finds = s.findings()
        score = max(0, 100 - sum(PENALTY[f.sev] for f in finds))
        grade = next(g for limit, g in ((90, "Healthy"), (70, "Needs attention"), (40, "Problems found"), (0, "Serious trouble")) if score >= limit)
        return dict(root=s.root, findings=finds, dirs=s.info, cats=dict(s.cat), largest=sorted(s.largest, reverse=True), score=score, grade=grade,
                    partial=s.stop.is_set(), stats=dict(files=s.files, dirs=s.dirs, bytes=s.bytes, depth=s.maxd, elapsed=time.time() - t0))

    def walk(s):
        stack = [(s.root, 0, None)]  # (folder, depth, parent)
        while stack and not s.stop.is_set():
            d, depth, parent = stack.pop()
            try:
                with os.scandir(d) as it:
                    entries = list(it)
            except OSError:
                s.add("unreadable", d)
                continue
            info = s.info[d] = {"size": 0, "files": 0, "children": [], "parent": parent}
            s.order.append(d)
            if depth == 13:
                s.add("deep", d)
            if len(entries) > 5000:
                s.add("big_dir", d)
            if not entries and depth:
                s.add("empty_dir", d)
            hid_dirs, lnks = set(), {}  # root only: hidden folder names, and .lnk files by name
            for e in entries:
                try:
                    is_dir = e.is_dir(follow_symlinks=False)
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    s.add("unreadable", e.path)
                    continue
                low, hid = e.name.lower(), s.hidden(e.name, st)
                s.check_name(e.name, e.path)
                if not is_dir:
                    s.scan_file(e, st, low, hid, depth == 0, info, lnks)
                elif low not in SKIP:
                    if re.match(r"found\.\d{3}$", low):
                        s.add("chkdsk_found", e.path)
                    if hid and depth == 0:
                        hid_dirs.add(low)
                        s.add("hidden_root", e.path)
                    info["children"].append(e.path)
                    stack.append((e.path, depth + 1, d))
                    s.dirs += 1
                    s.maxd = max(s.maxd, depth + 1)
            for stem, p in lnks.items():
                if stem in hid_dirs:
                    s.add("shortcut_virus", p)
            if time.time() - s.last > 0.1:
                s.last = time.time()
                s.q.put(("p", s.files, s.dirs, s.bytes, d))

    def scan_file(s, e, st, low, hid, is_root, info, lnks):
        full, size, ext = e.path, st.st_size, os.path.splitext(low)[1]
        info["size"] += size
        info["files"] += 1
        s.files += 1
        s.bytes += size
        s.cat[next((k for k, v in CATS.items() if ext in v), "Other")] += size
        if size == 0:
            s.add("zero_byte", full)
        if low in JUNK or low.startswith("._"):
            s.add("junk", full)
        elif low.startswith("~$") or ext in TEMP:
            s.add("temp", full)
        if ext == ".chk":
            s.add("chkdsk_found", full)
        if DOUBLE.search(low):
            s.add("double_ext", full)
        if is_root:
            if low == "autorun.inf":
                s.add("autorun", full)
            elif ext in EXEC:
                s.add("hidden_exec" if hid else "root_exec", full)
            elif ext == ".lnk":
                lnks[low[:-4]] = full
        heapq.heappush(s.largest, (size, full))
        if len(s.largest) > 10:
            heapq.heappop(s.largest)
        if s.deep and size:
            s.read_test(full, size)

    def roll_up(s):
        """Add each folder's totals into its parent (children are visited after parents, so go backwards)."""
        for p in s.info.values():
            p["tsize"], p["tfiles"] = p["size"], p["files"]
        for path in reversed(s.order):
            par = s.info.get(s.info[path]["parent"])
            if par:
                par["tsize"] += s.info[path]["tsize"]
                par["tfiles"] += s.info[path]["tfiles"]

    def findings(s):
        finds = []
        for key, n in s.counts.items():
            sev, title, detail, fix = RULES[key]
            finds.append(Finding(sev, title, n, detail, fix, s.items[key]))
        try:
            u = shutil.disk_usage(s.root)
            pct = u.free * 100 / u.total if u.total else 100
            if pct < 5:
                finds.append(Finding("high" if pct < 1 else "medium", "Drive almost full", 1, f"Only {fmt(u.free)} ({pct:.1f}%) is free. Full flash drives slow down and are more likely to corrupt files.", "Move or delete files to free at least 10%.", [s.root]))
        except OSError:
            pass
        if s.fs.lower() in {"fat", "fat32", "vfat", "msdos"}:
            finds.append(Finding("info", "FAT32 file system", 1, "Single files are limited to 4 GB and FAT has no crash protection, so pulling the drive without ejecting can corrupt it.", "Use exFAT or NTFS for large files, and always eject before unplugging.", [s.root]))
        return sorted(finds, key=lambda f: (ORDER[f.sev], -f.count))


# ---------------------------------------------------------------- drives and files
def usage(p):
    try:
        u = shutil.disk_usage(p)
        return dict(total=u.total, used=u.used, free=u.free)
    except OSError:
        return dict(total=0, used=0, free=0)


def windows_drives(show_all):
    out, k = [], ctypes.windll.kernel32
    mask = k.GetLogicalDrives()
    for i, letter in enumerate(string.ascii_uppercase):
        if not mask >> i & 1:
            continue
        p = f"{letter}:\\"
        kind = k.GetDriveTypeW(p)  # 2 = removable, 3 = fixed
        if kind != 2 and not (show_all and kind == 3):
            continue
        vol, fs = ctypes.create_unicode_buffer(261), ctypes.create_unicode_buffer(261)
        k.GetVolumeInformationW(p, vol, 261, None, None, None, fs, 261)
        out.append(dict(path=p, label=vol.value, fs=fs.value, removable=kind == 2, **usage(p)))
    return out


def mac_drives():
    paths = [os.path.join("/Volumes", n) for n in sorted(os.listdir("/Volumes"))]
    return [dict(path=p, label=os.path.basename(p), fs="", removable=True, **usage(p)) for p in paths if not os.path.islink(p)]


def linux_drives(show_all):
    out = []
    try:
        with open("/proc/mounts") as f:
            mounts = [line.split()[:3] for line in f]
    except OSError:
        return out
    for dev, mp, fs in mounts:
        mp = mp.replace("\\040", " ")
        removable = mp.startswith(("/media/", "/run/media/"))
        internal = show_all and dev.startswith("/dev/") and mp not in ("/", "/boot", "/boot/efi") and not mp.startswith("/snap")
        if removable or internal:
            out.append(dict(path=mp, label=os.path.basename(mp), fs=fs, removable=removable, **usage(mp)))
    return out


def list_drives(show_all):
    return windows_drives(show_all) if WIN else mac_drives() if MAC else linux_drives(show_all)


def reveal(path):
    """Open a folder, or show a file in its folder."""
    try:
        if WIN and os.path.isdir(path):
            os.startfile(path)
        elif WIN:
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        elif MAC:
            subprocess.Popen(["open", "-R", path])
        else:
            subprocess.Popen(["xdg-open", path if os.path.isdir(path) else os.path.dirname(path)])
    except Exception as ex:
        messagebox.showerror("FLS_CheckR", f"Could not open that location.\n{ex}")


def find_tool(name):
    """Look for PhotoRec/TestDisk next to this script (and one folder down), then on PATH."""
    exes = {"photorec": ("photorec_win.exe", "qphotorec_win.exe", "photorec"),
            "testdisk": ("testdisk_win.exe", "testdisk")}[name]
    base = os.path.dirname(os.path.abspath(__file__))
    try:
        subs = [os.path.join(base, d) for d in sorted(os.listdir(base)) if os.path.isdir(os.path.join(base, d))]
    except OSError:
        subs = []
    for folder in [base] + subs:
        for exe in exes:
            p = os.path.join(folder, exe)
            if os.path.isfile(p):
                return p
    return next((p for p in map(shutil.which, exes) if p), None)


def find_autorun(root):
    try:
        return next((os.path.join(root, n) for n in os.listdir(root) if n.lower() == "autorun.inf"), None)
    except OSError:
        return None


def quarantine_autorun(path):
    """Rename autorun.inf so it can no longer run. Reversible: rename it back."""
    new, i = path + ".FLS_CheckR-bak", 1
    while os.path.exists(new):
        i += 1
        new = f"{path}.FLS_CheckR-bak{i}"
    os.rename(path, new)
    return new


def same_drive(src, dest):
    """True if `dest` is on the same drive as `src` (or inside it)."""
    a, b = os.path.abspath(src), os.path.abspath(dest)
    da, db = os.path.splitdrive(a)[0].lower(), os.path.splitdrive(b)[0].lower()
    if da or db:
        return da == db
    try:
        return os.path.commonpath([a, b]) == a
    except ValueError:
        return False


def load_bad_hashes():
    """Read known-bad SHA-256 hashes from bad_hashes.txt next to this script ('hash name' per line)."""
    out, path = {}, os.path.join(os.path.dirname(os.path.abspath(__file__)), "bad_hashes.txt")
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    h, _, name = line.partition(" ")
                    out[h.lower()] = name.strip() or "listed in bad_hashes.txt"
    except OSError:
        pass
    return out


def report_text(r):
    st = r["stats"]
    lines = [f"FLS_CheckR report  -  {r['root']}", f"Health {r['score']}/100 ({r['grade']})",
             f"{st['files']:,} files, {st['dirs']:,} folders, {fmt(st['bytes'])}, depth {st['depth']}", ""]
    for f in r["findings"]:
        lines += [f"[{f.sev.upper()}] {f.title} ({f.count})", f"  {f.detail}", f"  Fix: {f.fix}"] + [f"    {p}" for p in f.items[:25]] + [""]
    lines.append("Largest files:")
    lines += [f"  {fmt(sz)}  {p}" for sz, p in r["largest"]]
    return "\n".join(lines)



# ---------------------------------------------------------------- custom widgets
def rrect(c, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return c.create_polygon(pts, smooth=True, **kw)


class FlatButton(tk.Canvas):
    def __init__(s, master, text, command, kind="primary", w=120, h=36, font=None):
        super().__init__(master, width=w, height=h, bg=master.cget("bg"), highlightthickness=0, bd=0, cursor="hand2")
        s.w, s.h, s.text, s.cmd, s.kind, s.font, s.on, s.hov = w, h, text, command, kind, font, True, False
        s.bind("<Enter>", lambda e: s.hover(True))
        s.bind("<Leave>", lambda e: s.hover(False))
        s.bind("<Button-1>", lambda e: s.on and s.cmd())
        s.draw()

    def hover(s, v):
        s.hov = v and s.on
        s.draw()

    def enable(s, v):
        s.on, s.hov = v, False
        s.configure(cursor="hand2" if v else "arrow")
        s.draw()

    def draw(s):
        s.delete("all")
        if s.kind == "primary":
            fill, fg, out = (ACCENT_D if s.hov else ACCENT) if s.on else "#B9C5CD", "#fff", None
        else:
            fill, fg, out = "#DCE5EA" if s.hov else s.cget("bg"), INK if s.on else "#9AA6B0", LINE
        rrect(s, 1, 1, s.w - 1, s.h - 1, 8, fill=fill, outline=out or fill)
        s.create_text(s.w / 2, s.h / 2, text=s.text, fill=fg, font=s.font)


class DriveCard(tk.Canvas):
    def __init__(s, master, d, font, pick):
        super().__init__(master, width=264, height=92, bg=PANEL, highlightthickness=0, cursor="hand2")
        s.d, s.f, s.sel = d, font, False
        s.bind("<Button-1>", lambda e: pick(d))
        s.draw()

    def mark(s, v):
        s.sel = v
        s.draw()

    def draw(s):
        d = s.d
        s.delete("all")
        rrect(s, 2, 2, 262, 90, 10, fill="#fff", outline=ACCENT if s.sel else LINE, width=2 if s.sel else 1)
        s.create_text(16, 12, anchor="nw", text=(d["label"] or "Untitled drive")[:26], font=(s.f, 11, "bold"), fill=INK)
        s.create_text(16, 34, anchor="nw", text=f'{d["path"]}   {d["fs"] or "file system unknown"}', font=(s.f, 9), fill=MUTED)
        s.create_rectangle(16, 58, 248, 64, fill=FREE, outline="")
        if d["total"]:
            r = d["used"] / d["total"]
            s.create_rectangle(16, 58, 16 + 232 * r, 64, fill=SEV["high"] if r > .95 else ACCENT, outline="")
            s.create_text(16, 68, anchor="nw", text=f'{fmt(d["used"])} used of {fmt(d["total"])}', font=(s.f, 8), fill=MUTED)


class CapBar(tk.Canvas):
    def __init__(s, master, font):
        super().__init__(master, height=50, bg=PANEL, highlightthickness=0)
        s.f, s.seg = font, []
        s.bind("<Configure>", lambda e: s.draw())

    def set(s, seg):
        s.seg = [x for x in seg if x[1] > 0]
        s.draw()

    def draw(s):
        s.delete("all")
        w, tot = s.winfo_width(), sum(x[1] for x in s.seg)
        if w < 20 or not tot:
            return
        x = 0
        for _, size, col in s.seg:
            x2 = x + (w - 2) * size / tot
            s.create_rectangle(x, 4, max(x2 - 2, x + 1), 22, fill=col, outline="")
            x = x2
        lx = 0
        for name, size, col in s.seg:
            s.create_rectangle(lx, 34, lx + 10, 44, fill=CAT_COL.get(name, col), outline="")
            t = s.create_text(lx + 15, 39, anchor="w", text=f"{name} {fmt(size)}", font=(s.f, 9), fill=MUTED)
            lx = s.bbox(t)[2] + 16


class Gauge(tk.Canvas):
    def __init__(s, master, font):
        super().__init__(master, width=128, height=128, bg=PANEL, highlightthickness=0)
        s.f = font
        s.set(None, "Not scanned")

    def set(s, score, cap):
        s.delete("all")
        s.create_arc(12, 12, 116, 116, start=225, extent=-270, style="arc", width=10, outline=LINE)
        col = INK
        if score is not None:
            col = GOOD if score >= 90 else SEV["medium"] if score >= 70 else SEV["high"]
            if score > 0:
                s.create_arc(12, 12, 116, 116, start=225, extent=-270 * score / 100, style="arc", width=10, outline=col)
        s.create_text(64, 56, text="--" if score is None else str(score), font=(s.f, 26, "bold"), fill=col)
        s.create_text(64, 84, text=cap, font=(s.f, 9), fill=MUTED)


def notches(e):
    """Wheel movement in notches (positive = up). Touchpads give fractions of a notch."""
    if e.num == 4:
        return 1.0
    if e.num == 5:
        return -1.0
    return e.delta * 0.4 if platform.system() == "Darwin" else e.delta / 120


def smooth_wheel(widget, target=None, step=3):
    """Scroll `target` (default: the widget) with mouse wheel or touchpad.
    Tk 8.6 drops small touchpad steps on Windows, so partial steps are added up here."""
    target, acc = target or widget, [0.0]

    def on_wheel(e):
        acc[0] -= notches(e) * step
        n = int(acc[0])
        if n:
            acc[0] -= n
            target.yview_scroll(n, "units")
        return "break"  # skip Tk's own handler so a mouse wheel doesn't scroll twice

    for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
        widget.bind(ev, on_wheel, add="+")


class FlatScroll(tk.Canvas):
    """Slim custom scrollbar: rounded thumb, hover and drag colours, click the track to jump."""
    MIN = 28

    def __init__(s, master, command, width=12, step=3):
        super().__init__(master, width=width, bg=master.cget("bg"), highlightthickness=0, bd=0)
        s.cmd, s.lo, s.hi, s.hover, s.drag = command, 0.0, 1.0, False, None
        smooth_wheel(s, command.__self__, step)  # wheel over the slider scrolls its list too
        s.bind("<Configure>", lambda e: s.draw())
        s.bind("<Enter>", lambda e: s.set_hover(True))
        s.bind("<Leave>", lambda e: s.set_hover(False))
        s.bind("<Button-1>", s.press)
        s.bind("<B1-Motion>", s.move)
        s.bind("<ButtonRelease-1>", s.release)

    def set(s, lo, hi):  # called by the scrolled widget
        s.lo, s.hi = float(lo), float(hi)
        s.draw()

    def set_hover(s, v):
        s.hover = v
        s.draw()

    def bounds(s):
        h = max(1, s.winfo_height())
        top, bot = s.lo * h, s.hi * h
        if bot - top < s.MIN:
            bot = top + s.MIN
            if bot > h:
                top, bot = h - s.MIN, h
        return h, top, bot

    def draw(s):
        s.delete("all")
        h, top, bot = s.bounds()
        if h < 16 or (s.lo <= 0 and s.hi >= 1):
            return  # nothing to scroll
        x = int(s.cget("width")) / 2
        s.create_line(x, 4, x, h - 4, width=4, capstyle="round", fill="#E1E7EC")
        col = ACCENT if s.drag else MUTED if s.hover else "#AAB6BF"
        s.create_line(x, top + 4, x, bot - 4, width=8, capstyle="round", fill=col)

    def press(s, e):
        h, top, bot = s.bounds()
        if s.lo <= 0 and s.hi >= 1:
            return
        if top <= e.y <= bot:
            s.drag = (e.y, s.lo)
        else:  # click on the track: centre the thumb there
            size = s.hi - s.lo
            target = min(max(e.y / h - size / 2, 0), 1 - size)
            s.cmd("moveto", target)
            s.drag = (e.y, target)
        s.draw()

    def move(s, e):
        if not s.drag:
            return
        h = max(1, s.winfo_height())
        y0, lo0 = s.drag
        size = s.hi - s.lo
        s.cmd("moveto", min(max(lo0 + (e.y - y0) / h, 0), max(0, 1 - size)))

    def release(s, e):
        s.drag = None
        s.draw()


def dot(color, size=12):
    img, c = tk.PhotoImage(width=size, height=size), (size - 1) / 2
    for x in range(size):
        for y in range(size):
            if (x - c) ** 2 + (y - c) ** 2 <= (size / 2 - .5) ** 2:
                img.put(color, (x, y))
    return img


# ---------------------------------------------------------------- widget helpers
def check(parent, text, var, bg, font, **kw):
    return tk.Checkbutton(parent, text=text, variable=var, bg=bg, fg=INK, activebackground=bg, selectcolor="#fff", font=font, **kw)


def entry(parent, var, font, **kw):
    return tk.Entry(parent, textvariable=var, font=(font, 10), relief="flat", bg="#fff", highlightthickness=1, highlightbackground=LINE, **kw)


def scrolled(parent, widget, step=3):
    """Pack `widget` with a FlatScroll beside it, and make the mouse wheel and touchpad scroll it."""
    bar = FlatScroll(parent, widget.yview, step=step)
    widget.configure(yscrollcommand=bar.set)
    bar.pack(side="right", fill="y")
    widget.pack(fill="both", expand=True)
    smooth_wheel(widget)
    return widget


def tree(parent, columns, **kw):
    """Scrolled Treeview. `columns` is a list of (column id, heading, width, anchor); the first id is '#0'."""
    t = ttk.Treeview(parent, columns=[c[0] for c in columns[1:]], **kw)
    for col, text, width, anchor in columns:
        t.heading(col, text=text, anchor=anchor)
        t.column(col, width=width, anchor=anchor)
    return scrolled(parent, t)


def set_text(widget, *parts):
    """Replace a read-only Text widget's content. Each part is (text,) or (text, tag)."""
    widget.config(state="normal")
    widget.delete("1.0", "end")
    for text, *tag in parts:
        widget.insert("end", text, *tag)
    widget.config(state="disabled")


def needs_drive(fn):
    """Run a sidebar action only when a drive is selected and no scan is running."""
    @functools.wraps(fn)
    def wrapper(s, *args):
        if s.sel and not s.scanning:
            return fn(s, *args)
    return wrapper


# ---------------------------------------------------------------- tool windows
class LogWindow(tk.Toplevel):
    """Base for tool windows: heading, option area, button bar, live log, and a worker thread that streams text."""

    def __init__(s, app, title, note, size="780x640"):
        super().__init__(app)
        s.app, s.q, s.busy, s.halt, s.btns, s.stopb, s.then = app, queue.Queue(), False, threading.Event(), [], None, None
        F = app.F
        s.title(title)
        s.geometry(size)
        s.configure(bg=BG)
        s.transient(app)
        head = tk.Frame(s, bg=BG)
        head.pack(fill="x", padx=20, pady=(18, 6))
        tk.Label(head, text=title, font=(F, 15, "bold"), bg=BG, fg=INK).pack(anchor="w")
        tk.Label(head, text=note, font=(F, 9), bg=BG, fg=MUTED, wraplength=730, justify="left").pack(anchor="w", pady=(2, 0))
        s.opts = tk.Frame(s, bg=BG)
        s.opts.pack(fill="x", padx=20)
        s.bar = tk.Frame(s, bg=BG)
        s.bar.pack(fill="x", padx=20, pady=10)
        s.stat = tk.Label(s, text="", font=(F, 9, "bold"), bg=BG, fg=ACCENT, anchor="w")
        s.stat.pack(fill="x", padx=20)
        box = tk.Frame(s, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        box.pack(fill="both", expand=True, padx=20, pady=(4, 20))
        s.mono = "Consolas" if "Consolas" in tkfont.families(s) else "Courier"
        s.out = tk.Text(box, bd=0, bg=PANEL, fg=INK, font=(s.mono, 10), padx=12, pady=10, wrap="word", state="disabled", highlightthickness=0)
        scrolled(box, s.out)
        s.protocol("WM_DELETE_WINDOW", s.close)

    def button(s, text, cmd, kind="ghost", w=150, lock=True):
        """Add a button to the bar. Locked buttons are disabled while a job runs."""
        b = FlatButton(s.bar, text, cmd, kind, w, 36, (s.app.F, 10, "bold"))
        b.pack(side="left", padx=(0, 8))
        if lock:
            s.btns.append(b)
        return b

    def write(s, text, clear=False):
        s.out.config(state="normal")
        if clear:
            s.out.delete("1.0", "end")
        s.out.insert("end", text)
        s.out.see("end")
        s.out.config(state="disabled")

    # Safe to call from the worker thread: they only put messages on the queue.
    def say(s, text):
        s.q.put(text)

    def status(s, text):
        s.q.put(("st", text))

    def line(s, text):
        """Called with each line of a command's output; subclasses can override to filter it."""
        s.say(text)

    def stream(s, cmd, answer=b""):
        """Run a command (Windows), show its output live, and return (exit code, all output)."""
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=NO_WINDOW)
        try:
            if answer:
                p.stdin.write(answer)
            p.stdin.close()
        except OSError:
            pass
        parts, buf = [], ""
        while chunk := p.stdout.read1(512):
            buf += chunk.decode("oem", "replace").replace("\r\n", "\n").replace("\r", "\n")
            *lines, buf = buf.split("\n")
            for ln in lines:
                parts.append(ln + "\n")
                s.line(ln + "\n")
        if buf:
            parts.append(buf)
            s.line(buf)
        return p.wait(), "".join(parts)

    def start(s, target, *args, header="", then=None):
        """Run target(*args) on a worker thread. `then(result)` is called on the UI thread when it ends."""
        if s.busy:
            return
        s.busy, s.then = True, then
        s.halt.clear()
        s.write(header, clear=True)
        s.lock(True)

        def run():
            try:
                res = target(*args)
            except Exception as ex:
                s.say(f"\nError: {ex}\n")
                res = None
            s.q.put(("end", res))
        threading.Thread(target=run, daemon=True).start()
        s.pump()

    def pump(s):
        try:
            while True:
                m = s.q.get_nowait()
                if not isinstance(m, tuple):
                    s.write(m)
                elif m[0] == "st":
                    s.stat.config(text=m[1])
                else:  # ("end", result)
                    s.busy = False
                    s.lock(False)
                    s.stat.config(text="")
                    if s.then:
                        s.then(m[1])
                    return
        except queue.Empty:
            pass
        s.after(100, s.pump)

    def lock(s, busy):
        for b in s.btns:
            b.enable(not busy)
        if s.stopb:
            s.stopb.enable(busy)

    def cancel(s):
        s.halt.set()
        s.stat.config(text="Stopping...")

    def close(s):
        if s.busy:
            messagebox.showinfo(s.title(), "Something is still running. Wait for it to finish (or press Stop).", parent=s)
            return
        s.destroy()


class ChkdskWindow(LogWindow):
    MSG = {0: "No errors found.", 2: "Cleanup was performed (or is needed).",
           3: "CHKDSK could not finish. It needs administrator rights, or the drive is in use or badly damaged."}

    def __init__(s, app, drive):
        note = admin_note("CHKDSK") or "Read-only check: reports problems without changing anything."
        super().__init__(app, f"CHKDSK - {drive}", note, "760x520")
        s.drive, s.fix = drive, tk.BooleanVar(value=False)
        check(s.opts, "Fix errors (/f) - may change the drive, so back up first", s.fix, BG, (app.F, 9)).pack(anchor="w", pady=(8, 0))
        s.button("Run CHKDSK", s.do_check, "primary", 140)
        s.button("Close", s.close, "ghost", 90, lock=False)

    def line(s, text):
        """Turn CHKDSK's endless 'N percent completed' lines into one live label."""
        m = re.match(r"\s*(\d+) percent completed", text)
        if m:
            s.status(f"{m.group(1)}% complete")
        else:
            s.say(text)

    def do_check(s):
        fix = s.fix.get()
        if fix and not messagebox.askokcancel("Fix errors", "CHKDSK /f can modify or delete damaged data on the drive.\nCopy your important files somewhere safe first.\n\nContinue?", parent=s):
            return
        cmd = ["chkdsk", s.drive] + (["/f"] if fix else [])
        # /f may ask "force a dismount?", so answer Y
        s.start(lambda: s.stream(cmd, b"Y\r\n" if fix else b"")[0], header=f"> {' '.join(cmd)}\n\n", then=lambda code: s.finish(code, fix))

    def finish(s, code, fix):
        if code is None:  # the error was already printed
            return
        if code == 1:
            msg = "Errors were found and fixed." if fix else "Errors were found. Back up your files, then tick Fix errors and run again."
        else:
            msg = s.MSG.get(code, f"CHKDSK exited with code {code}.")
        s.write(f"\n{msg}\n")
        s.app.status.config(text=f"CHKDSK on {s.drive}: {msg}")


class RescueWindow(LogWindow):
    """Copies every readable file off a damaged drive, skipping (and listing) the ones that fail."""

    def __init__(s, app, src):
        note = (f"Copies every file that can still be read from {src} and keeps the folder layout. Files that fail are skipped and listed below. "
                "Nothing on the drive is changed, and you can run it again to resume.")
        super().__init__(app, "Rescue files", note, "720x560")
        s.src, s.dest, s.total = src, tk.StringVar(), max(1, app.sel["used"])
        F = app.F
        tk.Label(s.opts, text="Save to (choose a different drive)", font=(F, 9, "bold"), bg=BG, fg=INK).pack(anchor="w", pady=(6, 0))
        row = tk.Frame(s.opts, bg=BG)
        row.pack(fill="x", pady=(4, 0))
        entry(row, s.dest, F).pack(side="left", fill="x", expand=True, ipady=6)
        FlatButton(row, "Browse", s.choose, "ghost", 90, 34, (F, 10, "bold")).pack(side="left", padx=(8, 0))
        s.button("Start rescue", s.do_start, "primary", 140)
        s.stopb = s.button("Stop", s.cancel, "ghost", 80, lock=False)
        s.stopb.enable(False)
        s.button("Close", s.close, "ghost", 90, lock=False)

    def choose(s):
        p = filedialog.askdirectory(title="Where should the rescued files go?", parent=s)
        if p:
            s.dest.set(os.path.normpath(p))

    def do_start(s):
        dest = s.dest.get().strip()
        problem = ("Choose a destination folder first." if not dest or not os.path.isdir(dest) else
                   "The destination is on the drive you are rescuing from. Pick a folder on a different drive so the damaged drive is not written to."
                   if same_drive(s.src, dest) else None)
        if problem:
            messagebox.showinfo("Rescue files", problem, parent=s)
            return
        if shutil.disk_usage(dest).free < s.total * 1.02 and not messagebox.askyesno("Rescue files", f"The destination may not have enough free space (about {fmt(s.total)} needed). Continue anyway?", parent=s):
            return
        s.start(s.work, dest, then=lambda msg: msg and s.app.status.config(text=msg))

    def copy(s, src, dst):
        with open(src, "rb") as a, open(dst, "wb") as b:
            while chunk := a.read(1 << 20):
                if s.halt.is_set():
                    raise OSError("stopped")
                b.write(chunk)
        try:
            shutil.copystat(src, dst)
        except OSError:
            pass

    def work(s, dest):
        label = re.sub(r'[<>:"/\\|?*]', "_", s.app.sel["label"] or "drive")
        out = os.path.join(dest, f"{label} rescue")
        done = nbytes = 0
        fails, stack, last = [], [s.src], 0.0

        def fail(path):
            fails.append(path)
            s.say(f"Could not copy: {path}\n")

        while stack and not s.halt.is_set():
            d = stack.pop()
            rel = os.path.relpath(d, s.src)
            tdir = out if rel == "." else os.path.join(out, rel)
            try:
                os.makedirs(tdir, exist_ok=True)
                with os.scandir(d) as it:
                    entries = list(it)
            except OSError:
                fail(d)
                continue
            for e in entries:
                if s.halt.is_set():
                    break
                try:
                    if e.is_dir(follow_symlinks=False):
                        if e.name.lower() not in SKIP:
                            stack.append(e.path)
                        continue
                    size = e.stat(follow_symlinks=False).st_size
                except OSError:
                    fail(e.path)
                    continue
                target = os.path.join(tdir, e.name)
                try:
                    if not (os.path.exists(target) and os.path.getsize(target) == size):  # else: already rescued earlier
                        s.copy(e.path, target)
                    done, nbytes = done + 1, nbytes + size
                except OSError:
                    try:
                        os.remove(target)
                    except OSError:
                        pass
                    if not s.halt.is_set():
                        fail(e.path)
                if time.time() - last > 0.15:
                    last = time.time()
                    s.status(f"{done:,} files copied, {fmt(nbytes)} of about {fmt(s.total)}. {len(fails)} could not be copied.")
        if fails:
            try:
                with open(os.path.join(out, "RESCUE_FAILED.txt"), "w", encoding="utf-8") as f:
                    f.write("\n".join(fails))
            except OSError:
                pass
        msg = f"{'Stopped' if s.halt.is_set() else 'Finished'}: {done:,} files ({fmt(nbytes)}) saved to {out}. {len(fails)} could not be copied."
        s.say(f"\n{msg}\n")
        return msg


class DiskpartWindow(LogWindow):
    """Run diskpart from the app: list disks, show details, or wipe and reformat a USB disk."""

    def __init__(s, app):
        note = admin_note("Diskpart") + "Lists the computer's disks and can wipe and reformat a USB disk. Wiping erases everything on it. Disk 0 and disks that are not USB are always refused."
        super().__init__(app, "Diskpart", note)
        F = app.F
        tk.Label(s.opts, text="Disks (press List disks, then pick yours by its size)", font=(F, 9, "bold"), bg=BG, fg=INK).pack(anchor="w", pady=(6, 0))
        s.lb = tk.Listbox(s.opts, height=5, exportselection=False, bd=0, bg="#fff", fg=INK, font=(s.mono, 9), highlightthickness=1,
                          highlightbackground=LINE, selectbackground="#D3E4EE", selectforeground=INK, activestyle="none")
        s.lb.pack(fill="x", pady=(4, 8))
        smooth_wheel(s.lb)
        row = tk.Frame(s.opts, bg=BG)
        row.pack(fill="x")
        s.fs, s.label, s.full = tk.StringVar(value="exfat"), tk.StringVar(value="USB"), tk.BooleanVar(value=False)
        for v in ("exfat", "ntfs", "fat32"):
            tk.Radiobutton(row, text=v.upper(), value=v, variable=s.fs, bg=BG, fg=INK, activebackground=BG, selectcolor="#fff", font=(F, 9)).pack(side="left", padx=(0, 10))
        tk.Label(row, text="Label", font=(F, 9), bg=BG, fg=INK).pack(side="left", padx=(10, 4))
        entry(row, s.label, F, width=14).pack(side="left", ipady=3)
        check(row, "Full format (slow, checks the whole drive)", s.full, BG, (F, 9)).pack(side="left", padx=14)
        s.button("List disks", s.do_list, "primary", 120)
        s.button("Disk details", s.do_detail, "ghost", 120)
        s.button("Wipe and format", s.do_wipe, "ghost", 150)
        s.button("Close", s.close, "ghost", 90, lock=False)

    def diskpart(s, lines):
        """Run diskpart commands from a temporary script; returns (exit code, output)."""
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(lines) + "\n")
        try:
            return s.stream(["diskpart", "/s", f.name])
        finally:
            try:
                os.remove(f.name)
            except OSError:
                pass

    def wipe(s, n, fs, label, full):
        text = s.diskpart([f"select disk {n}", "detail disk"])[1]
        if "USB" not in text.upper():
            s.say("\nRefused: this disk is not reported as a USB disk.\n")
            return
        s.say("\n--- Wiping and formatting ---\n")
        fmt_cmd = f"format fs={fs}" + ("" if full else " quick") + (f" label={label}" if label else "")
        out = s.diskpart([f"select disk {n}", "clean", "create partition primary", fmt_cmd, "assign"])[1].lower()
        ok = "successfully formatted" in out or "100 percent" in out
        s.say("\nDone. Press Refresh in FLS_CheckR to see the drive.\n" if ok else "\nCheck the output above. If it shows an error, the drive may not accept the format.\n")

    def disk_no(s):
        """The (disk number, list line) selected in the list, or None."""
        sel = s.lb.curselection()
        if not sel:
            messagebox.showinfo("Diskpart", "Press List disks, then pick a disk in the list.", parent=s)
            return None
        line = s.lb.get(sel[0])
        m = re.match(r"\s*\S+\s+(\d+)\s", line)
        return (int(m.group(1)), line.strip()) if m else None

    def fill_disks(s, result):
        if not result:
            return
        s.lb.delete(0, "end")
        for ln in result[1].splitlines():
            if re.match(r"\s*\S+\s+\d+\s{2,}", ln):
                s.lb.insert("end", ln.rstrip())

    def do_list(s):
        s.start(s.diskpart, ["list disk"], header="> list disk\n\n", then=s.fill_disks)

    def do_detail(s):
        r = s.disk_no()
        if r:
            s.start(s.diskpart, [f"select disk {r[0]}", "detail disk"], header=f"> select disk {r[0]} / detail disk\n\n")

    def do_wipe(s):
        r = s.disk_no()
        if not r:
            return
        n, line = r
        if n == 0:
            messagebox.showerror("Diskpart", "Disk 0 is normally your computer's main drive, so it is never wiped here.", parent=s)
            return
        typed = simpledialog.askstring("Erase disk", f"This ERASES everything on Disk {n}:\n{line}\n\nType  ERASE {n}  to continue.", parent=s)
        if (typed or "").strip().upper() != f"ERASE {n}":
            return
        fs = s.fs.get()
        label = re.sub(r"[^A-Za-z0-9_-]", "", s.label.get())[: 11 if fs == "fat32" else 32]
        s.start(s.wipe, n, fs, label, s.full.get(), header=f"> wipe disk {n}, {fs}\n\n", then=lambda _: s.app.refresh())


class VirusWindow(LogWindow):
    """Virus check: Microsoft Defender does the real scan; a built-in quick check adds a few extra signs."""

    def __init__(s, app, path):
        super().__init__(app, "Virus scan", f"Scans {path}. Microsoft Defender does the real virus detection. The quick check only finds the EICAR test virus, disguised double-extension files, known-bad hashes from bad_hashes.txt and suspicious scripts, so it does not replace antivirus.")
        s.path, s.report = path, tk.BooleanVar(value=True)
        check(s.opts, "Report only (Defender will not remove or quarantine anything)", s.report, BG, (app.F, 9)).pack(anchor="w", pady=(6, 0))
        s.button("Scan with Defender", s.do_defender, "primary", 170)
        s.button("Quick check", lambda: s.start(s.quick), "ghost", 120)
        s.button("Update definitions", s.do_update, "ghost", 160)
        s.stopb = s.button("Stop", s.cancel, "ghost", 80, lock=False)
        s.stopb.enable(False)
        s.button("Close", s.close, "ghost", 90, lock=False)

    def windows_only(s):
        if not WIN:
            messagebox.showinfo("Virus scan", "Microsoft Defender is Windows only. On Linux install ClamAV and run:\n  clamscan -r /path/to/drive\n\nThe Quick check button still works here.", parent=s)
        return WIN

    def do_defender(s):
        if s.windows_only():
            args = ["-Scan", "-ScanType", "3", "-File", s.path] + (["-DisableRemediation"] if s.report.get() else [])
            s.start(s.defender, args, "No threats found.")

    def do_update(s):
        if s.windows_only():
            s.start(s.defender, ["-SignatureUpdate"], "Virus definitions are up to date.")

    def defender(s, args, ok_msg):
        exe = find_defender()
        if not exe:
            s.say("Microsoft Defender's command-line tool (MpCmdRun.exe) was not found. Another antivirus may be replacing it. Use that program to scan the drive instead.\n")
            return
        s.say(f"> MpCmdRun {' '.join(args)}\n\n")
        code, _ = s.stream([exe] + args)
        if code == 0:
            s.say(f"\n{ok_msg}\n")
        else:
            s.say(f"\nDefender finished with code {code}. If it found threats, open Windows Security > Virus & threat protection > Protection history. It may also need administrator rights.\n")

    def sha256(s, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                if s.halt.is_set():
                    return ""
                h.update(chunk)
        return h.hexdigest()

    def inspect(s, p, folder, bad):
        """Return the suspicious signs found in one file (may raise OSError)."""
        low = os.path.basename(p).lower()
        ext, size, hits = os.path.splitext(low)[1], os.path.getsize(p), []
        if low == "autorun.inf" and os.path.normpath(folder) == os.path.normpath(s.path):
            hits.append("autorun.inf at drive root")
        if DOUBLE.search(low):
            hits.append("disguised program (double extension)")
        if 0 < size <= 1024:
            with open(p, "rb") as f:
                if EICAR in f.read(1024):
                    hits.append("EICAR antivirus test file (a harmless test, not a real virus)")
        if bad and (ext in EXEC or ext in {".dll", ".msi", ".lnk"}) and size <= 100 << 20:
            digest = s.sha256(p)
            if digest in bad:
                hits.append(f"matches known-bad hash: {bad[digest]}")
        if ext in SCRIPT_EXT and size <= 1 << 20:
            with open(p, "rb") as f:
                data = f.read().lower()
            hits += [f"script contains '{x.decode()}'" for x in SCRIPT_PATTERNS if x in data][:3]
        return hits

    def quick(s):
        bad, n, found = load_bad_hashes(), 0, 0
        s.say(f"Quick check of {s.path}  ({len(bad)} known-bad hashes loaded from bad_hashes.txt)\n\n")
        for folder, dirs, files in os.walk(s.path):
            dirs[:] = [x for x in dirs if x.lower() not in SKIP]
            for name in files:
                if s.halt.is_set():
                    break
                p = os.path.join(folder, name)
                try:
                    hits = s.inspect(p, folder, bad)
                except OSError:
                    continue
                n += 1
                if n % 200 == 0:
                    s.status(f"Checked {n:,} files...")
                if hits:
                    found += 1
                    s.say(f"[!] {p}\n" + "".join(f"      - {h}\n" for h in hits))
            if s.halt.is_set():
                break
        s.say(f"\n{'Stopped. ' if s.halt.is_set() else ''}Checked {n:,} files, {found} suspicious.\n")
        s.say("Nothing suspicious found. This does not prove the drive is clean, so run the Defender scan as well.\n" if not found else
              "Suspicious files are not always viruses. Run the Defender scan on them before deleting anything.\n")


# ---------------------------------------------------------------- main window
class App(tk.Tk):
    def __init__(s):
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
        super().__init__()
        s.title("FLS_CheckR - flash drive inspector")
        s.geometry("1200x780")
        s.minsize(1000, 720)
        s.configure(bg=BG)
        fams = set(tkfont.families(s))
        s.F = next((f for f in ("Segoe UI", "SF Pro Text", "Inter", "Ubuntu", "Noto Sans", "DejaVu Sans") if f in fams), "Helvetica")
        s.drives, s.cards, s.sel, s.result, s.scanning, s.pos = [], [], None, None, False, 0
        s.filter, s.fmap = "all", {}
        s.show_all, s.deep = tk.BooleanVar(value=False), tk.BooleanVar(value=False)
        s.dots = {k: dot(c) for k, c in SEV.items()}
        s.style()
        s.build()
        s.refresh()

    def style(s):
        st = ttk.Style(s)
        st.theme_use("clam")
        st.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        st.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=INK, rowheight=30, borderwidth=0, font=(s.F, 10))
        st.configure("Treeview.Heading", background=BG, foreground=MUTED, relief="flat", font=(s.F, 9, "bold"), padding=(8, 6))
        st.map("Treeview", background=[("selected", "#D3E4EE")], foreground=[("selected", INK)])
        st.map("Treeview.Heading", background=[("active", BG)])
        st.configure("Vertical.TScrollbar", background=LINE, troughcolor=PANEL, borderwidth=0, arrowsize=12)

    def lbl(s, p, text, size=10, bold=False, fg=INK, bg=None, **kw):
        return tk.Label(p, text=text, font=(s.F, size, "bold" if bold else "normal"), fg=fg, bg=bg or p.cget("bg"), **kw)

    # ---- layout
    def build(s):
        side = tk.Frame(s, bg=PANEL, width=300)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Frame(s, bg=LINE, width=1).pack(side="left", fill="y")
        s.build_sidebar(side)
        main = tk.Frame(s, bg=BG)
        main.pack(side="left", fill="both", expand=True, padx=26, pady=22)
        s.build_header(main)
        s.build_summary(main)
        s.build_tabs(main)
        foot = tk.Frame(main, bg=BG)
        foot.pack(fill="x", pady=(10, 0))
        s.status = s.lbl(foot, "Ready", 9, fg=MUTED)
        s.status.pack(anchor="w")
        s.prog = tk.Canvas(foot, height=4, bg=LINE, highlightthickness=0)
        s.prog.pack(fill="x", pady=(4, 0))
        s.tab("Problems")
        s.set_filter("all")

    def build_sidebar(s, side):
        s.lbl(side, "FLS_CheckR", 20, True).pack(anchor="w", padx=20, pady=(22, 2))
        s.lbl(side, "Inspect a flash drive's folders and files, and see what is wrong with it.", 9, fg=MUTED, wraplength=256, justify="left").pack(anchor="w", padx=20)
        s.lbl(side, "Drives", 10, True).pack(anchor="w", padx=20, pady=(22, 6))
        wrap = tk.Frame(side, bg=PANEL)
        wrap.pack(fill="x", padx=(14, 6))
        s.cv = tk.Canvas(wrap, bg=PANEL, width=266, height=204, highlightthickness=0, yscrollincrement=1)
        bar = FlatScroll(wrap, s.cv.yview, step=40)
        s.cv.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        s.cv.pack(side="left")
        s.cardbox = tk.Frame(s.cv, bg=PANEL)
        s.cv.create_window((0, 0), window=s.cardbox, anchor="nw")
        s.cardbox.bind("<Configure>", lambda e: s.cv.configure(scrollregion=s.cv.bbox("all")))
        smooth_wheel(s.cv, step=40)
        smooth_wheel(s.cardbox, s.cv, 40)

        opts = tk.Frame(side, bg=PANEL)
        opts.pack(fill="x", padx=18, pady=(10, 0))
        for text, var, cmd in (("Show internal drives", s.show_all, s.refresh), ("Read-test every file (slower, finds bad sectors)", s.deep, None)):
            check(opts, text, var, PANEL, (s.F, 9), command=cmd, anchor="w", wraplength=240, justify="left").pack(fill="x", pady=2)
        row = tk.Frame(side, bg=PANEL)
        row.pack(fill="x", padx=18, pady=14)
        FlatButton(row, "Refresh", s.refresh, "ghost", 120, 34, (s.F, 10)).pack(side="left")
        FlatButton(row, "Browse folder", s.browse, "ghost", 130, 34, (s.F, 10)).pack(side="right")

        s.lbl(side, "Rescue and repair", 10, True).pack(anchor="w", padx=20, pady=(4, 4))
        grid = tk.Frame(side, bg=PANEL)
        grid.pack(padx=16)
        s.tools = []  # buttons that need a selected drive
        specs = (("Rescue files", s.open_rescue), ("Run CHKDSK", s.open_chkdsk),
                 ("Disable autorun", s.fix_autorun), ("Open drive", s.open_drive),
                 ("PhotoRec", lambda: s.open_recovery("photorec")), ("TestDisk", lambda: s.open_recovery("testdisk")),
                 ("Virus scan", s.open_virus), ("Diskpart", s.open_diskpart))
        for i, (text, cmd) in enumerate(specs):
            b = FlatButton(grid, text, cmd, "ghost", 128, 34, (s.F, 9, "bold"))
            b.grid(row=i // 2, column=i % 2, padx=2, pady=3)
            if text != "Diskpart":  # Diskpart must work even when no drive has a letter
                b.enable(False)
                s.tools.append(b)

    def build_header(s, main):
        head = tk.Frame(main, bg=BG)
        head.pack(fill="x")
        t = tk.Frame(head, bg=BG)
        t.pack(side="left")
        s.title_l = s.lbl(t, "No drive selected", 17, True)
        s.title_l.pack(anchor="w")
        s.sub_l = s.lbl(t, "Choose a drive on the left, then scan it.", 10, fg=MUTED)
        s.sub_l.pack(anchor="w")
        btns = tk.Frame(head, bg=BG)
        btns.pack(side="right")
        s.exp_btn = FlatButton(btns, "Save report", s.export, "ghost", 110, 38, (s.F, 10, "bold"))
        s.stop_btn = FlatButton(btns, "Stop", s.stop_scan, "ghost", 80, 38, (s.F, 10, "bold"))
        s.scan_btn = FlatButton(btns, "Scan drive", s.start, "primary", 130, 38, (s.F, 10, "bold"))
        for b in (s.exp_btn, s.stop_btn, s.scan_btn):
            b.pack(side="left", padx=(8, 0))
            b.enable(False)

    def build_summary(s, main):
        box = tk.Frame(main, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        box.pack(fill="x", pady=16)
        s.gauge = Gauge(box, s.F)
        s.gauge.pack(side="left", padx=18, pady=10)
        mid = tk.Frame(box, bg=PANEL)
        mid.pack(side="left", fill="x", expand=True, padx=(0, 22))
        s.cap = CapBar(mid, s.F)
        s.cap.pack(fill="x", pady=(14, 8))
        tiles = tk.Frame(mid, bg=PANEL)
        tiles.pack(fill="x")
        s.v = {}  # tile name -> value label
        for name in ("Files", "Folders", "Data scanned", "Deepest folder", "Problems"):
            f = tk.Frame(tiles, bg=PANEL)
            f.pack(side="left", padx=(0, 30))
            s.v[name] = s.lbl(f, "--", 15, True)
            s.v[name].pack(anchor="w")
            s.lbl(f, name, 9, fg=MUTED).pack(anchor="w")

    def build_tabs(s, main):
        bar = tk.Frame(main, bg=BG)
        bar.pack(fill="x")
        s.tabs = {}  # tab name -> (label, underline)
        for name in ("Problems", "Structure"):
            f = tk.Frame(bar, bg=BG)
            f.pack(side="left", padx=(0, 22))
            label = s.lbl(f, name, 11, True, MUTED, cursor="hand2")
            label.pack(pady=(0, 4))
            label.bind("<Button-1>", lambda e, n=name: s.tab(n))
            underline = tk.Frame(f, height=3, bg=BG)
            underline.pack(fill="x")
            s.tabs[name] = (label, underline)
        tk.Frame(main, bg=LINE, height=1).pack(fill="x")
        body = tk.Frame(main, bg=BG)
        body.pack(fill="both", expand=True, pady=(10, 0))
        s.build_problems(body)
        s.sf = tk.Frame(body, bg=PANEL)  # structure tab
        s.st = tree(s.sf, [("#0", "Folder", 420, "w"), ("size", "Size", 110, "e"), ("files", "Files", 90, "e"), ("share", "Share of drive", 120, "e")])

    def build_problems(s, body):
        s.pf = tk.Frame(body, bg=BG)
        chips = tk.Frame(s.pf, bg=BG)
        chips.pack(fill="x", pady=(0, 8))
        s.chips = {}
        for key, name in (("all", "All"), ("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Info")):
            c = tk.Label(chips, text=name, font=(s.F, 9, "bold"), padx=12, pady=4, cursor="hand2")
            c.pack(side="left", padx=(0, 6))
            c.bind("<Button-1>", lambda e, k=key: s.set_filter(k))
            s.chips[key] = c
        # detail panel (explanation on the left, affected items on the right)
        det = tk.Frame(s.pf, bg=PANEL, height=190, highlightthickness=1, highlightbackground=LINE)
        det.pack(side="bottom", fill="x", pady=(10, 0))
        det.pack_propagate(False)
        s.text = tk.Text(det, wrap="word", bd=0, bg=PANEL, fg=INK, font=(s.F, 10), padx=14, pady=10, width=40, highlightthickness=0, state="disabled", cursor="arrow")
        s.text.pack(side="left", fill="both", expand=True)
        s.text.tag_configure("h", font=(s.F, 12, "bold"), spacing3=4)
        s.text.tag_configure("k", font=(s.F, 9, "bold"), foreground=MUTED, spacing1=8)
        right = tk.Frame(det, bg=PANEL)
        right.pack(side="right", fill="both", expand=True, padx=(0, 10), pady=10)
        s.lbl(right, "Affected items (double-click to open its location)", 9, True, MUTED).pack(anchor="w")
        s.lb = tk.Listbox(right, bd=0, bg="#fff", fg=INK, font=(s.F, 9), highlightthickness=1, highlightbackground=LINE, selectbackground="#D3E4EE", selectforeground=INK, activestyle="none")
        s.lb.pack(fill="both", expand=True, pady=(4, 0))
        s.lb.bind("<Double-1>", lambda e: s.lb.curselection() and reveal(s.lb.get(s.lb.curselection()[0])))
        smooth_wheel(s.text)
        smooth_wheel(s.lb)
        # list of problems
        tw = tk.Frame(s.pf, bg=PANEL)
        tw.pack(fill="both", expand=True)
        s.ft = tree(tw, [("#0", "Problem", 420, "w"), ("lvl", "Severity", 100, "w"), ("n", "Found", 80, "e")], selectmode="browse")
        s.ft.bind("<<TreeviewSelect>>", s.show_detail)
        s.empty = s.lbl(tw, "Select a drive and press Scan drive.", 11, fg=MUTED)
        s.empty.place(relx=.5, rely=.4, anchor="center")

    def tab(s, name):
        for n, (label, underline) in s.tabs.items():
            label.configure(fg=INK if n == name else MUTED)
            underline.configure(bg=ACCENT if n == name else BG)
        s.pf.pack_forget()
        s.sf.pack_forget()
        (s.pf if name == "Problems" else s.sf).pack(fill="both", expand=True)

    def set_filter(s, key):
        s.filter = key
        for k, c in s.chips.items():
            c.configure(bg=INK if k == key else "#D5DDE3", fg="#fff" if k == key else INK)
        s.fill_findings()

    # ---- drives
    def refresh(s):
        if s.scanning:
            return
        keep = s.sel["path"] if s.sel else None
        s.drives = list_drives(s.show_all.get()) + [d for d in s.drives if d.get("custom")]
        s.show_drives(keep)

    def browse(s):
        p = filedialog.askdirectory(title="Choose a drive or folder to scan")
        if p and not s.scanning:
            s.drives.append(dict(path=p, label=os.path.basename(p) or p, fs="", removable=False, custom=True, **usage(p)))
            s.show_drives(p)

    def show_drives(s, keep):
        """Rebuild the drive cards and select the drive at path `keep` (or the first one)."""
        for c in s.cards:
            c.destroy()
        s.cards = []
        for d in s.drives:
            c = DriveCard(s.cardbox, d, s.F, s.pick)
            c.pack(pady=4)
            smooth_wheel(c, s.cv, 40)
            s.cards.append(c)
        s.sel = None
        if not s.drives:
            s.title_l.config(text="No flash drive found")
            s.sub_l.config(text="Plug one in and press Refresh, or browse to a folder.")
            s.scan_btn.enable(False)
            for b in s.tools:
                b.enable(False)
            return
        s.pick(next((d for d in s.drives if d["path"] == keep), s.drives[0]))

    def pick(s, d):
        if s.scanning:
            return
        s.sel, s.result = d, None
        for c in s.cards:
            c.mark(c.d is d)
        s.title_l.config(text=f'{d["label"] or "Untitled drive"}  ({d["path"]})')
        s.sub_l.config(text=f'{d["fs"] or "File system unknown"}, {fmt(d["total"])} total, {fmt(d["free"])} free')
        s.scan_btn.enable(True)
        s.exp_btn.enable(False)
        for b in s.tools:
            b.enable(True)
        s.gauge.set(None, "Not scanned")
        s.cap.set([("Used", d["used"], ACCENT), ("Free", d["free"], FREE)])
        for label in s.v.values():
            label.config(text="--")
        s.clear_results("Press Scan drive to look for problems.")
        s.status.config(text="Ready")

    # ---- scanning
    def set_scanning(s, on):
        s.scanning = on
        s.scan_btn.enable(not on)
        s.stop_btn.enable(on)

    def start(s):
        if not s.sel or s.scanning:
            return
        s.set_scanning(True)
        s.q, s.stop = queue.Queue(), threading.Event()
        s.exp_btn.enable(False)
        s.clear_results("Scanning...")
        threading.Thread(target=Scanner(s.sel["path"], s.sel["fs"], s.deep.get(), s.q, s.stop).run, daemon=True).start()
        s.poll()
        s.tick()

    def stop_scan(s):
        s.stop.set()
        s.status.config(text="Stopping...")

    def poll(s):
        try:
            while True:
                m = s.q.get_nowait()
                if m[0] == "p":  # ("p", files, folders, bytes, current folder)
                    s.status.config(text=f"Scanning {m[4]}")
                    s.show_counts(m[1], m[2], m[3])
                elif m[0] == "error":
                    s.set_scanning(False)
                    messagebox.showerror("FLS_CheckR", f"The scan failed:\n{m[1]}")
                    return
                else:  # ("done", result)
                    s.finish(m[1])
                    return
        except queue.Empty:
            pass
        if s.scanning:
            s.after(80, s.poll)

    def tick(s):
        """Animate the moving bar at the bottom while scanning."""
        s.prog.delete("all")
        if not s.scanning:
            return
        w = max(s.prog.winfo_width(), 200)
        s.pos = (s.pos + 14) % (w + 180)
        s.prog.create_rectangle(s.pos - 180, 0, s.pos, 4, fill=ACCENT, outline="")
        s.after(30, s.tick)

    def show_counts(s, files, folders, nbytes):
        s.v["Files"].config(text=f"{files:,}")
        s.v["Folders"].config(text=f"{folders:,}")
        s.v["Data scanned"].config(text=fmt(nbytes))

    def finish(s, r):
        s.set_scanning(False)
        s.result = r
        s.exp_btn.enable(True)
        st, d = r["stats"], s.sel
        s.show_counts(st["files"], st["dirs"], st["bytes"])
        s.v["Deepest folder"].config(text=f'{st["depth"]} levels')
        s.v["Problems"].config(text=str(sum(1 for f in r["findings"] if f.sev in ("high", "medium"))))
        s.gauge.set(r["score"], r["grade"])
        segments = [(k, v, CAT_COL[k]) for k, v in r["cats"].items()]
        gap = d["used"] - st["bytes"]  # space used on the drive that the scan did not see
        if gap > d["total"] * .01:
            segments.append(("Unscanned", gap, CAT_COL["Unscanned"]))
        s.cap.set(segments + [("Free", d["free"], FREE)])
        s.fill_findings()
        s.fill_structure(r)
        s.status.config(text=f'{"Stopped early" if r["partial"] else "Scan complete"} in {st["elapsed"]:.1f} s')

    # ---- results
    def clear_results(s, message):
        s.ft.delete(*s.ft.get_children())
        s.st.delete(*s.st.get_children())
        s.empty.config(text=message)
        s.empty.place(relx=.5, rely=.4, anchor="center")
        s.clear_detail()

    def fill_findings(s):
        s.ft.delete(*s.ft.get_children())
        s.fmap = {}
        s.clear_detail()
        if not s.result:
            return
        for f in s.result["findings"]:
            if s.filter in ("all", f.sev):
                iid = s.ft.insert("", "end", text="  " + f.title, image=s.dots[f.sev], values=(f.sev.capitalize(), f"{f.count:,}"))
                s.fmap[iid] = f
        if s.fmap:
            s.empty.place_forget()
        else:
            s.empty.config(text="No problems found. This drive looks clean." if not s.result["findings"] else "Nothing in this category.")
            s.empty.place(relx=.5, rely=.4, anchor="center")

    def clear_detail(s):
        set_text(s.text)
        s.lb.delete(0, "end")

    def show_detail(s, _=None):
        sel = s.ft.selection()
        if not sel:
            return
        f = s.fmap[sel[0]]
        set_text(s.text, (f.title + "\n", "h"), (f.detail + "\n",), ("What to do\n", "k"), (f.fix,))
        s.lb.delete(0, "end")
        for p in f.items:
            s.lb.insert("end", p)
        if f.count > len(f.items):
            s.lb.insert("end", f"... and {f.count - len(f.items):,} more")

    def fill_structure(s, r):
        s.st.delete(*s.st.get_children())
        dirs, root = r["dirs"], r["root"]
        if root not in dirs:
            return
        total, n = max(1, dirs[root]["tsize"]), [0]

        def add(parent, path, depth):
            kids = sorted((c for c in dirs[path]["children"] if c in dirs), key=lambda c: -dirs[c]["tsize"])[:80]
            for c in kids:
                if n[0] > 4000:
                    return
                n[0] += 1
                i = dirs[c]
                iid = s.st.insert(parent, "end", text="  " + os.path.basename(c), values=(fmt(i["tsize"]), f'{i["tfiles"]:,}', f'{i["tsize"] * 100 / total:.1f}%'))
                if depth < 4:
                    add(iid, c, depth + 1)
        add("", root, 1)

    # ---- sidebar actions
    def open_diskpart(s):
        if s.scanning:
            return
        if not WIN:
            messagebox.showinfo("Diskpart", "Diskpart only exists on Windows.\n\nOn Linux use  lsblk  to find the disk, then  sudo wipefs -a /dev/sdX  and  sudo mkfs.exfat /dev/sdX1.\nOn macOS use Disk Utility.")
            return
        DiskpartWindow(s)

    @needs_drive
    def open_virus(s):
        VirusWindow(s, s.sel["path"])

    @needs_drive
    def open_rescue(s):
        RescueWindow(s, s.sel["path"])

    def open_drive(s):
        if s.sel:
            reveal(s.sel["path"])

    @needs_drive
    def open_recovery(s, name):
        title = "PhotoRec" if name == "photorec" else "TestDisk"
        if not WIN:
            messagebox.showinfo(title, f"{title} runs in a terminal. Unmount the drive, then run:\n  sudo {name}\n\nSave recovered files to a different drive.")
            return
        path = find_tool(name)
        if not path:
            if not messagebox.askyesno(title, f"{title} was not found next to FLS_CheckR.\n\nPut the unzipped TestDisk & PhotoRec folder (or its .exe files) in the same folder as FLS_CheckR.py and press this button again. It is a free download from cgsecurity.org.\n\nDo you want to choose the program file yourself instead?"):
                return
            path = filedialog.askopenfilename(title=f"Choose {title}", filetypes=[("Programs", "*.exe"), ("All files", "*.*")])
            if not path:
                return
        if not messagebox.askokcancel(title, f"{title} will open in its own window. When it asks where to save recovered files, choose a folder on a different drive, never on {s.sel['path']}."):
            return
        try:
            subprocess.Popen([path], cwd=os.path.dirname(path) or None, creationflags=0x10)  # CREATE_NEW_CONSOLE
        except OSError as ex:
            messagebox.showerror(title, f"Could not start {title}.\n{ex}")

    @needs_drive
    def open_chkdsk(s):
        p = s.sel["path"]
        if not WIN:
            messagebox.showinfo("CHKDSK", "CHKDSK only exists on Windows.\n\nOn Linux, unmount the drive and run:\n  sudo fsck -n /dev/sdX1\n\nOn macOS, use Disk Utility > First Aid.")
        elif len(p) < 2 or p[1] != ":":
            messagebox.showinfo("CHKDSK", "CHKDSK needs a drive, not a folder. Pick a drive from the list.")
        else:
            ChkdskWindow(s, p[:2])

    @needs_drive
    def fix_autorun(s):
        f = find_autorun(s.sel["path"])
        if not f:
            messagebox.showinfo("autorun.inf", "No autorun.inf was found at the root of this drive.")
            return
        try:
            with open(f, "r", errors="replace") as fh:
                body = fh.read(600)
        except OSError:
            body = "(could not be read)"
        if not messagebox.askyesno("Disable autorun.inf", f"Found:\n{f}\n\nContents:\n{body}\n\nRename it to autorun.inf.FLS_CheckR-bak so it can no longer run? You can rename it back at any time."):
            return
        try:
            new = quarantine_autorun(f)
        except OSError as ex:
            messagebox.showerror("autorun.inf", f"Could not rename the file.\n{ex}")
            return
        s.status.config(text=f"autorun.inf disabled as {os.path.basename(new)}. Scan again to confirm.")

    def export(s):
        if not s.result:
            return
        p = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text report", "*.txt")], initialfile="FLS_CheckR-report.txt")
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(report_text(s.result))
            s.status.config(text=f"Report saved to {p}")


if __name__ == "__main__":
    App().mainloop()
