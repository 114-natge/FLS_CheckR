# FLS_CheckR

FLS_CheckR is a small desktop app that scans a flash drive, shows its folder structure, and lists what is wrong with it. It also has tools to rescue files from a damaged drive.

It is a hobby tool written in Python. Use it at your own risk, and keep a second copy of anything important. I think theres bug on it cuz it's still (WIP). Sorry for the inconvenience :(

## What it does

- Scans a drive and gives it a health score from 0 to 100.
- Lists problems by severity (high, medium, low, info), with an explanation and a suggested fix for each.
- Shows a folder tree sorted by size, plus a bar of what fills the drive (documents, media, archives, programs, free space).
- Copies readable files off a damaged drive (**Rescue files**).
- Runs CHKDSK, disables a dangerous `autorun.inf`, and starts PhotoRec or TestDisk.
- Saves a text report of the scan.

The scan and **Rescue files** only read the drive. The tools that can change the drive are **Run CHKDSK** with "Fix errors" ticked and **Disable autorun**, and both ask first.

## Requirements

- PhotoRec and TestDisk(literally free :))
- Python 3.8 or newer. No extra packages are needed.
- Tkinter, which comes with Python on Windows and macOS. On Linux, install it with `sudo apt install python3-tk`.
- Windows is the main target. The scan works on Linux and macOS too, but CHKDSK and the PhotoRec/TestDisk launchers are Windows only.

## How to run

```
python FLS_CheckR.py
```

1. Plug in the drive and pick it in the left list. Press **Refresh** if it isn't there.
2. Press **Scan drive**.
3. Read the **Problems** tab. Click a problem to see what it means, what to do, and which files are affected. Double-click an affected path to open its location.

For CHKDSK, start the app with **Run as administrator**.

## Folder layout

To use PhotoRec and TestDisk from the app, put them next to the app:

```
FLS_CheckR.py
README.md
testdisk-7.x/            (the unzipped TestDisk & PhotoRec folder)
    photorec_win.exe
    testdisk_win.exe
```

The app looks in its own folder, then one folder down, then on your PATH. Both programs are free from cgsecurity.org.

## The buttons

| Button | What it does |
| --- | --- |
| Scan drive / Stop | Scans the selected drive. Stop ends the scan early and keeps what it found. |
| Save report | Saves the results as a text file. |
| Rescue files | Copies every readable file to a folder on a different drive. |
| Run CHKDSK | Opens a window that checks the drive (Windows only). |
| Disable autorun | Renames `autorun.inf` so it can no longer run. |
| Open drive | Opens the drive in your file manager. |
| PhotoRec / TestDisk | Starts the recovery program if it is installed next to the app. |

Two options sit under the drive list:

- **Show internal drives** adds fixed drives. Some flash drives are reported as fixed by Windows.
- **Read-test every file** reads the start and end of each file to find bad sectors. It is slower, but it catches real flash failures.

## What the scan looks for

| Severity | Examples |
| --- | --- |
| High | `autorun.inf`, shortcut-virus pattern, files like `photo.jpg.exe`, hidden programs at the drive root, files that fail to read, folders that cannot be read, drive almost full |
| Medium | CHKDSK leftovers (`FOUND.000`, `.chk`), programs at the drive root, bad names, paths near 260 characters |
| Low | Empty files, empty folders, temporary files, very deep folders, folders with over 5,000 entries, hidden items at the root |
| Info | System clutter such as `Thumbs.db` and `.DS_Store`, FAT32 file system note |

The health score starts at 100 and loses points for each type of problem found: 14 for high, 6 for medium and 2 for low. Each problem list shows up to 300 affected items.

## FAQ

### Is it safe? Will it change my files?

Scanning only reads the drive. **Rescue files** copies files off the drive and does not change it. **Run CHKDSK** with "Fix errors" ticked can modify or delete damaged data, so it asks you to confirm first. **Disable autorun** renames one file and you can rename it back.

### My drive isn't in the list.

Press **Refresh**. If it is still missing, tick **Show internal drives**, or use **Browse folder** and choose the drive. If Windows shows the drive in Disk Management but without a letter, right-click its partition, choose **Change Drive Letter and Paths**, and add a letter. If the drive isn't in Disk Management at all, try another USB port without a hub, or another computer.

### What does "Folders or entries that cannot be read" mean?

The drive's file index is damaged, so the scan couldn't read some folders. Press **Rescue files** first to copy out what still reads. Only then try CHKDSK, because a repair can delete damaged entries. For files that are still missing, try TestDisk, then PhotoRec.

### The drive shows as RAW. What should I do?

Don't format it, don't click Initialize, and don't run `chkdsk /f`. Use **TestDisk** first, because it can often find the lost partition and bring the folders back with their names. If that finds nothing, use **PhotoRec**, which finds files by their contents but loses the original names and folders. Save recovered files to a different drive.

### What is the difference between TestDisk and PhotoRec?

TestDisk repairs partitions and file systems and can copy files out with their names. PhotoRec ignores the file system and finds files by their contents. Try TestDisk first and PhotoRec second.

### The drive shows 1 MB (or 0 B) instead of its real size.

The drive's controller has crashed and is reporting a tiny fallback size. FLS_CheckR, TestDisk and PhotoRec can only see that small size, so they can't recover files from it. If you only want the drive to work again, wipe it in diskpart:

```
diskpart
list disk
select disk N
clean
create partition primary
format fs=exfat quick
assign
```

Replace `N` with your flash drive's number from `list disk`. Check the size before you select it, because `clean` erases the selected disk, and `select disk 0` is usually your computer's main drive. If `clean` doesn't help, a manufacturer tool for your drive's controller may reset it. Search for the drive's VID and PID on flashboot.ru. The tool erases the drive.

### How do I use `list disk`?

Open Command Prompt as administrator, type `diskpart`, then `list disk`. Your flash drive is the disk that matches its size, and a 32 GB drive shows as about 29 GB. To be sure, unplug the drive and run `list disk` again. The disk that disappears is the one you want. Never select Disk 0 unless you are certain it is the right one.

### CHKDSK is stuck at a percentage.

CHKDSK can sit on one percentage for a long time on a damaged drive. If the drive's activity light is blinking, wait up to an hour. If nothing moves after that, stop it, plug the drive into another port, and try again without `/f`. If it hangs again, the drive's hardware is probably failing.

### Run CHKDSK says it needs administrator rights.

Close FLS_CheckR and start it again with **Run as administrator**. Without that, CHKDSK reports "Access Denied".

### Run CHKDSK says it needs a drive, not a folder.

CHKDSK works on drive letters only. If you used **Browse folder**, pick the drive from the list instead.

### Why does the app only list removable drives?

So it is hard to scan or repair your main drive by mistake. Tick **Show internal drives** if your flash drive shows up as a fixed disk.

### What is the shortcut-virus pattern?

Shortcut (`.lnk`) files with the same names as hidden folders. The virus hides your real folders and leaves shortcuts that run a program. Scan with antivirus, then in Command Prompt run `attrib -h -r -s /s /d X:\*.*` (replace `X` with the drive letter) to unhide your folders, and delete the shortcuts.

### Why does Rescue files refuse my destination?

The destination can't be on the drive you are rescuing from, so the damaged drive is never written to. Pick a folder on a different drive. You can run it again later and it skips files that were already copied.

### Where do rescued files go?

Into a folder called `<drive label> rescue` inside the destination you picked. Files that could not be copied are listed in the window and in `RESCUE_FAILED.txt` in that folder.

### Does it work on Linux or macOS?

The scan, the folder tree, Rescue files and Disable autorun work. CHKDSK and the PhotoRec/TestDisk launchers are Windows only, and on Linux and macOS the app shows the terminal command or tool to use instead (`fsck`, Disk Utility, `sudo photorec`).

### How do I use Diskpart in the app?

Press **Diskpart** (it works even when no drive has a letter) and start FLS_CheckR with **Run as administrator**. Press **List disks**, pick your flash drive by its size, and press **Disk details** to check it. **Wipe and format** erases the disk, creates one partition, formats it (exFAT, NTFS or FAT32) and gives it a drive letter. It refuses Disk 0 and any disk that is not reported as USB, and you must type `ERASE N` to confirm. Tick **Full format** for a slow format that checks the whole drive.

### Does it have a virus scanner?

Press **Virus scan**. **Scan with Defender** runs Microsoft Defender's command-line scanner on the drive. It is on by default as "report only", so nothing is removed until you untick that box. **Update definitions** fetches the latest virus definitions, which needs internet. **Quick check** is FLS_CheckR's own light check: it finds the EICAR test file, disguised double-extension programs, scripts with suspicious commands, and files whose SHA-256 hash is listed in an optional `bad_hashes.txt` next to the app (one hash per line, an optional name after a space, `#` for comments). It does not replace antivirus. On Linux or macOS only the quick check works, so use ClamAV for a full scan.

### Can I scroll with a touchpad?

Yes. Two-finger scrolling and the mouse wheel work in all the lists and logs, and you can also drag the custom slider on the right edge.

### The scan is slow.

Large drives with many files take time, and **Read-test every file** makes it slower. You can press **Stop** to end the scan early, and the results so far are kept.

### How do I know the drive is healthy again?

Copy some files onto it, scan it with **Read-test every file** ticked, and make sure the scan has no high-severity problems. Always eject the drive before unplugging it. If the corruption or the wrong size returns, the drive is failing and should be replaced.

## Limitations

- It can't recover files from a drive whose controller has failed. Only a professional data recovery service can.
- It can't repair a damaged file system by itself. It points you to CHKDSK, TestDisk or a reformat.
- It doesn't replace antivirus. It only flags suspicious patterns.
- The duplicate-file check mentioned in earlier versions isn't included.

## Credits

PhotoRec and TestDisk are free programs by Christophe Grenier (cgsecurity.org). FLS_CheckR only starts them and is not affiliated with them.
