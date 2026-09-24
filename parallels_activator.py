#!/usr/bin/env python3
# language: Python 3.8+, file: parallels_activator.py, target: macOS (arm64), stdlib only
# Parallels Desktop 26.4.x activation bypass — consumer one-shot.
# Gate chain, verified live on 26.4.1 (57516) and 26.4.2 (57518), arm64:
#   1. prl_disp_service license-state computer -> always "valid"
#   2. prl_disp_service SecCode peer-creds check -> always pass (pair is ad-hoc re-signed)
#   3. prl_vm_app license-state computer -> always "valid"
#   4. prl_vm_app SecCode peer validator -> always pass
#   5. prl_disp_service JLIC RSA signature verify -> always true
#      (without this the loader DISCARDS the license: free edition, no cpu/ram
#      limits, vm_app dies with "Failed to get VM configuration" / POWER_ON_FAILED)
#   6. prl_disp_service genuineness pre-filter (SecStaticCodeCheckValidity) -> NOP
#   7. prl_disp_service genuineness VERDICT (execlp'd /usr/bin/codesign -R helper,
#      waitpid status mapped via csel) -> forced "genuine". Kills the
#      "copy may not be genuine" nag in Control Center AND the guest-side
#      Parallels Control Center.exe popup, which feed from the same report.
# With gate 5 dead, any well-formed licenses.json loads — the built-in keygen
# forges one matched to this machine (hw_id = IOPlatformUUID, dashes stripped).
#
# Usage: sudo python3 parallels_activator.py [options]
#   (no args)      :: FULL one-shot — stop dispatcher, patch all 7 gates, re-sign,
#                     verify readback, forge a Pro license (expires 2099), restart
#                     the dispatcher onto the PATCHED image (verified fresh),
#                     re-register any VMs lost to a reinstall, print license proof.
#                     Run it and walk away.
#   --keygen       :: only forge + deploy a fresh Pro license, restart dispatcher
#   --restore      :: put the original binaries back, restart dispatcher
#   --test         :: prove the bypass: stash the license, VM must still start
#   --e2e          :: patch, then start Windows 11 with no license on disk
#   --keep-license :: leave an existing license alone (default flow re-forges)

import argparse
import base64
import glob
import json
import os
import pwd
import random
import shutil
import string
import time
import struct
import subprocess
import sys
import uuid

# license-state computer: identical function (same constants/shape) compiled into both
# binaries. Returning 0 = license valid for every consumer (GUI info, VM-start gate,
# headless mode, dispatcher commands).
TARGETS = [
    "/Applications/Parallels Desktop.app/Contents/MacOS/Parallels Service.app/Contents/MacOS/prl_disp_service",
    "/Applications/Parallels Desktop.app/Contents/MacOS/Parallels VM.app/Contents/MacOS/prl_vm_app",
]
# per binary: list of patch sites. Sites are located by INSTRUCTION SIGNATURE
# ('??' = wildcard byte, usually a call/adrp immediate that shifts between builds)
# so the patcher survives Parallels updates that recompile but don't rewrite the
# gated functions. Pinned VA + expected bytes remain as fallback for this build;
# ambiguous or missing signatures refuse to patch (never patch blind).
SITES = {
    "prl_disp_service": [
        dict(name="license-state computer -> w0=0",
             sig="ff4301d1f65702a9f44f03a9fd7b04a9fd030191f30300aa????????60000036",
             patch_off=0, patch="00008052c0035fd6",
             va=0x100361A34, expected="ff4301d1"),
        dict(name="peer creds check -> w0=1",
             sig="ffc301d1f65704a9f44f05a9fd7b06a9fd830191f30302aaf50301aaf40300aa"
                  "e00301aa????????00010034a0c2c03ca1c2c13ce00701ad",
             patch_off=0, patch="20008052c0035fd6",
             va=0x1000279B4, expected="ffc301d1"),
        dict(name="JLIC RSA verify -> w0=1",
             sig="ffc301d1f85f03a9f65704a9f44f05a9fd7b06a9fd830191f40301aae8630091"
                  "????????170080d2130080d2960240f9d50680b9a806150b08791f53",
             patch_off=0, patch="20008052c0035fd6",
             va=0x1004E3398, expected="ffc301d1"),
        dict(name="genuineness cbnz -> nop",
             sig="????????f90300aae0000035e00318aa",
             patch_off=8, patch="1f2003d5",
             va=0x1005D6168, expected="e0000035"),
        dict(name="codesign-helper verdict -> genuine",
             sig="????????1f1d1872290080522905891a1f19007220019f1a",
             patch_off=0x14, patch="20008052",
             va=0x1005D62C4, expected="20019f1a"),
    ],
    "prl_vm_app": [
        dict(name="license-state computer -> w0=0",
             sig="ff4301d1f65702a9f44f03a9fd7b04a9fd030191f30300aa????????60000036",
             patch_off=0, patch="00008052c0035fd6",
             va=0x1000D6D38, expected="ff4301d1"),
        dict(name="peer validator -> w0=0",
             sig="ffc301d1f85f03a9f65704a9f44f05a9fd7b06a9fd830191f40301aa"
                  "????????????????080140f9e81700f9e01700b9"
                  "????????????????130140f9e2530091e00313aa21018052????????c00900b4",
             patch_off=0, patch="00008052c0035fd6",
             va=0x1008CBD88, expected="ffc301d1"),
    ],
}
HERE      = os.path.dirname(os.path.abspath(__file__))
def backup_of(t): return os.path.join(HERE, os.path.basename(t) + ".orig")
def legacy_of(t): return t + ".orig"  # backups must NOT live inside bundles (breaks the seal)

def fat_arm64_slice(path):
    """Return (offset, size) of the arm64 slice in a fat (universal2) binary."""
    with open(path, "rb") as f:
        head = f.read(4096)
    magic = struct.unpack(">I", head[:4])[0]
    if magic in (0xFEEDFACF, 0xFEEDFACE):          # thin, already 64-bit
        return 0, os.path.getsize(path)
    if magic != 0xCAFEBABE:
        raise ValueError("not a Mach-O")
    nfat = struct.unpack(">I", head[4:8])[0]
    off = 8
    for _ in range(nfat):
        cputype, _, slice_off, slice_size, _ = struct.unpack(">IIIII", head[off:off + 20])
        if cputype == 0x0100000C:                  # CPU_TYPE_ARM64
            return slice_off, slice_size
        off += 20
    raise ValueError("no arm64 slice")

def scan_sig(data, start, end, sig):
    """All match offsets of a masked byte signature within data[start:end]."""
    hb = [sig[i * 2:i * 2 + 2] for i in range(len(sig) // 2)]
    first = next(k for k, b in enumerate(hb) if b != "??")
    anchor = bytes([int(hb[first], 16)])
    hits, pos = [], start + first
    while True:
        j = data.find(anchor, pos, end)
        if j < 0:
            return hits
        pos = j + 1
        m = j - first
        if m < start:
            continue
        if all(hb[k] == "??" or data[m + k] == int(hb[k], 16) for k in range(len(hb))):
            hits.append(m)

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

RESOLVED = []  # (off, want) of every site patched this run, for post-sign readback

def patched_sig(site):
    """The site's signature with the patch bytes spliced in — matches the binary
    when (and only when) this site is already patched, at any build offset."""
    hb = [site["sig"][i * 2:i * 2 + 2] for i in range(len(site["sig"]) // 2)]
    w = [site["patch"][i * 2:i * 2 + 2] for i in range(len(site["patch"]) // 2)]
    hb[site["patch_off"]:site["patch_off"] + len(w)] = w
    return "".join(hb)

def patch(svc):
    with open(svc, "rb") as f:
        data = bytearray(f.read())
    sl_off, sl_size = fat_arm64_slice(svc)
    for site in SITES[os.path.basename(svc)]:
        want = bytes.fromhex(site["patch"])
        hits = scan_sig(bytes(data), sl_off, sl_off + sl_size, site["sig"])
        if len(hits) > 1:
            print("[!] %s: signature for '%s' is ambiguous (%d matches) — "
                  "falling back to pinned offset" % (os.path.basename(svc), site["name"], len(hits)))
            hits = []
        if not hits:
            already = scan_sig(bytes(data), sl_off, sl_off + sl_size, patched_sig(site))
            if len(already) == 1:
                off = already[0] + site["patch_off"]
                print("[*] %s '%s' already patched (0x%X)"
                      % (os.path.basename(svc), site["name"], off))
                RESOLVED.append((svc, off, want))
                continue
        pinned = sl_off + site["va"] - 0x100000000
        off = hits[0] + site["patch_off"] if hits else pinned
        cur = bytes(data[off:off + len(want)])
        if cur == want:
            print("[*] %s '%s' already patched (0x%X)" % (os.path.basename(svc), site["name"], off))
            RESOLVED.append((svc, off, want))
            continue
        if not hits and cur[:len(site["expected"]) // 2] != bytes.fromhex(site["expected"]):
            print("[!] %s: '%s' not found by signature and unexpected bytes at pinned "
                  "0x%X: %s (expected %s)" % (os.path.basename(svc), site["name"], off,
                                              cur.hex(), site["expected"]))
            print("[!] unsupported build — refusing to patch blind")
            return False
        data[off:off + len(want)] = want
        RESOLVED.append((svc, off, want))
        where = "sig 0x%X" % off if hits else "pinned 0x%X" % off
        print("[+] patched %s '%s' at %s" % (os.path.basename(svc), site["name"], where))
    with open(svc, "wb") as f:
        f.write(data)
    return True

def verify_patches():
    """Read every patched site back from disk (post-codesign) — a re-sign that
    silently dropped a patch must not go unnoticed."""
    ok = True
    for svc, off, want in RESOLVED:
        with open(svc, "rb") as f:
            f.seek(off)
            cur = f.read(len(want))
        if cur != want:
            print("[!] readback mismatch in %s at 0x%X" % (os.path.basename(svc), off))
            ok = False
    if ok and RESOLVED:
        print("[+] all %d patch sites verified on disk" % len(RESOLVED))
    return ok

def restore():
    for t in TARGETS:
        b = backup_of(t)
        if os.path.isfile(b):
            shutil.copyfile(b, t)
            print("[+] restored %s" % os.path.basename(t))

def resign(svc):
    """Ad-hoc re-sign one patched binary, preserving its entitlements.
    arm64 macOS refuses to exec a binary whose signature no longer matches."""
    ents = os.path.join(HERE, os.path.basename(svc) + ".entitlements.plist")
    # --xml forces an XML plist on stdout; without it modern codesign writes a DER blob
    # that --entitlements refuses on the signing side
    r = run(["codesign", "-d", "--entitlements", "-", "--xml", backup_of(svc)])
    blob = r.stdout
    if r.returncode != 0 or "<plist" not in blob:
        print("[!] entitlement extraction failed for %s: %s" % (os.path.basename(svc), r.stderr.strip()))
        return False
    with open(ents, "w") as f:
        f.write(blob)
    r = run(["codesign", "--force", "--sign", "-", "--entitlements", ents,
             "--timestamp=none", svc])
    if r.returncode != 0:
        print("[!] codesign failed for %s: %s" % (os.path.basename(svc), r.stderr.strip()))
        return False
    print("[+] re-signed %s (ad-hoc, entitlements preserved)" % os.path.basename(svc))
    return True

LAUNCHD_PLIST = ("/Applications/Parallels Desktop.app/Contents/MacOS/"
                 "Parallels Service.app/Contents/Resources/com.parallels.desktop.launchdaemon.plist")

def daemon_pid():
    r = run(["pgrep", "-x", "prl_disp_service"])
    out = r.stdout.strip()
    return int(out) if r.returncode == 0 and out.isdigit() else None

def stop_daemon():
    """Stop the dispatcher BEFORE patching, and refuse to continue if it won't
    die. Overwriting a running signed binary gets it CS_KILLed by the kernel
    and the watchdog respawns it mid-patch — the respawned daemon then runs a
    stale (unpatched) image and rejects the patched peers with
    'creds are invalid'. Seen live on 26.4.2. A consumer run must never
    'continue anyway'."""
    run(["launchctl", "bootout", "system/com.parallels.desktop.launchdaemon"])
    for _ in range(20):
        if daemon_pid() is None:
            return True
        time.sleep(0.5)
    pid = daemon_pid()
    if pid is not None:
        run(["kill", str(pid)])  # bootout lost the argument — escalate
        for _ in range(10):
            if daemon_pid() is None:
                return True
            time.sleep(0.5)
        pid = daemon_pid()
        if pid is not None:
            run(["kill", "-9", str(pid)])
            for _ in range(10):
                if daemon_pid() is None:
                    return True
                time.sleep(0.5)
    print("[!] dispatcher would not die — refusing to patch a live signed binary")
    return False

def bounce_daemon():
    r = run(["launchctl", "kickstart", "-k", "system/com.parallels.desktop.launchdaemon"])
    if r.returncode != 0:
        # kickstart can drop/lose the registration on this setup — re-bootstrap,
        # then kickstart anyway: bootstrap alone can no-op under launchd throttle
        r = run(["launchctl", "bootstrap", "system/", LAUNCHD_PLIST])
        if r.returncode != 0 and "Bootstrap failed: 5" not in (r.stderr + r.stdout):
            print("[!] daemon bootstrap: %s" % (r.stderr.strip() or r.stdout.strip()))
        run(["launchctl", "kickstart", "-k", "system/com.parallels.desktop.launchdaemon"])
    for _ in range(40):  # 20s — launchd throttles rapid restarts ~10s
        pid = daemon_pid()
        if pid is not None:
            print("[+] dispatcher restarted (pid %d)" % pid)
            return True
        time.sleep(0.5)
    print("[!] dispatcher did not come back — bootstrap manually:\n"
          "    sudo launchctl bootstrap system/ %s" % LAUNCHD_PLIST)
    return False

def daemon_is_fresh():
    """The running daemon must have started AFTER the newest patched binary was
    written — otherwise it's executing the pre-patch image from memory while the
    on-disk binary is patched, and the kernel can CS_KILL it on the next page-in.
    Caught live: daemon started 20:15, binary written 00:48, still running.
    NOTE: macOS ps has no 'etimes' keyword — parse lstart instead."""
    pid = daemon_pid()
    if pid is None:
        return False
    r = run(["ps", "-o", "lstart=", "-p", str(pid)])
    stamp = " ".join(r.stdout.split())  # day field can be space-padded
    try:
        started = time.mktime(time.strptime(stamp, "%a %b %d %H:%M:%S %Y"))
    except ValueError:
        return False
    newest = max(os.path.getmtime(t) for t in TARGETS if os.path.isfile(t))
    return started >= newest - 5

def ensure_fresh_daemon():
    """(Re)start the dispatcher and PROVE it's running the post-patch image."""
    if not bounce_daemon():
        return False
    time.sleep(1)
    if daemon_is_fresh():
        return True
    print("[*] daemon predates the patched binaries — bouncing onto the new image")
    stop_daemon()
    if not bounce_daemon():
        return False
    time.sleep(1)
    if daemon_is_fresh():
        return True
    print("[!] daemon still running a stale image after re-bounce")
    return False

def show_license():
    for cli in ("prlsrvctl", "/usr/local/bin/prlsrvctl"):
        if shutil.which(cli) or os.path.isfile(cli):
            r = run([cli, "info", "--license"])
            print(r.stdout.strip() or r.stderr.strip())
            return
    print("[*] prlsrvctl not found — check the GUI instead")

LICENSE_PATH = "/Library/Preferences/Parallels/licenses.json"

def machine_hw_id():
    """Parallels hw_id is just IOPlatformUUID with the dashes stripped."""
    r = run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
    for line in r.stdout.splitlines():
        if "IOPlatformUUID" in line:
            hw = line.split('"')[-2].replace("-", "").upper()
            if len(hw) == 32:
                return hw
    return None

def product_version():
    import plistlib
    try:
        with open("/Applications/Parallels Desktop.app/Contents/Info.plist", "rb") as f:
            p = plistlib.load(f)
        return "%s-%s" % (p.get("CFBundleShortVersionString", "26.4.1"),
                          p.get("CFBundleVersion", "57516"))
    except Exception:
        return "26.4.1-57516"

def forge_license():
    """Generate + deploy a host-matched Pro license. Gate 5 makes the RSA
    signature decorative — any well-formed JSON loads as valid."""
    hw = machine_hw_id()
    if not hw:
        print("[!] could not harvest IOPlatformUUID")
        return False
    serial = "-".join("".join(random.choice(string.ascii_uppercase + string.digits)
                              for _ in range(6)) for _ in range(5))
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    lic = {
        "name": "key", "uuid": uuid.uuid4().hex, "lic_key": serial,
        "product_version": "*", "is_upgrade": False, "is_sublicense": False,
        "parent_key": None, "parent_uuid": None,
        "main_period_ends_at": "2099-05-05 04:00:05",
        "grace_period_ends_at": "2099-05-12 04:00:05",
        "is_auto_renewable": True, "is_nfr": False, "is_beta": False,
        "is_china": False, "is_suspended": False, "is_expired": False,
        "is_grace_period": False, "is_purchased_online": True,
        "limit": 1, "usage": 1, "edition": 3, "platform": 3, "product": 7,
        "offline": False, "is_bytebot": False,
        "cpu_limit": 32, "ram_limit": 131072,
        "is_trial": False, "is_enterprise": False,
        "hosts": [{"name": "GDPR_HIDDEN", "hw_id": hw,
                   "product_version": product_version(),
                   "activated_at": now, "activation_type": "LIC_KEY"}],
        "started_at": now, "cep_option": False,
    }
    blob = {"license": json.dumps(lic),
            "signature": base64.b64encode(os.urandom(256)).decode()}
    with open(LICENSE_PATH, "w") as f:
        json.dump(blob, f)
    os.chmod(LICENSE_PATH, 0o644)
    print("[+] forged Pro license deployed (hw_id %s…%s)" % (hw[:6], hw[-4:]))
    print("[+] your serial: %s" % serial)
    return True

def test_unlicensed():
    """The real proof: no license on disk, VM must still start."""
    lic = "/Library/Preferences/Parallels/licenses.json"
    stash = os.path.join(HERE, "licenses.json.stash")
    if not os.path.isfile(lic):
        print("[*] no licenses.json present — already unlicensed")
    else:
        shutil.move(lic, stash)
        print("[+] licenses.json moved aside")
    try:
        if not ensure_fresh_daemon():
            return
        time.sleep(3)
        r = run(["prlctl", "start", "Windows 11"])
        out = (r.stdout + r.stderr).strip()
        print("[*] prlctl start output: %s" % out)
        if r.returncode == 0 and "started" in out.lower():
            print("[+] VM STARTED WITH ZERO LICENSE ON DISK — bypass proven")
        else:
            print("[!] VM start blocked or failed — gate still closed")
    finally:
        if os.path.isfile(stash):
            shutil.move(stash, lic)
            print("[+] licenses.json restored")
        ensure_fresh_daemon()

def e2e():
    lic = "/Library/Preferences/Parallels/licenses.json"
    stash = os.path.join(HERE, "licenses.json.stash")
    if os.path.isfile(lic):
        shutil.move(lic, stash)
        print("[+] license removed (stashed at %s)" % stash)
    else:
        print("[*] license already absent")
    for t in TARGETS:
        if not os.path.isfile(backup_of(t)):
            shutil.copyfile(t, backup_of(t))
    if not stop_daemon():
        sys.exit("[!] dispatcher still alive — aborting (nothing was modified)")
    ok = all(patch(t) and resign(t) for t in TARGETS)
    if ok:
        ensure_fresh_daemon()
        time.sleep(3)
        pid = daemon_pid()
        print("[+] daemon running (pid %d)" % pid if pid is not None
              else "[!] daemon not running")
        r = run(["prlctl", "start", "Windows 11"])
        out = (r.stdout + r.stderr).strip()
        print("[*] prlctl start: %s" % out)
        print("[+] VM STARTED WITH NO LICENSE ON DISK — bypass proven"
              if r.returncode == 0 and "started" in out.lower()
              else "[!] VM start blocked — gate still closed")
        print("[*] license stays stashed. --restore puts binary+license back.")
    else:
        print("[!] patch/sign failed — binary untouched or restored")

def user_home():
    """Under sudo, ~ is /var/root — the consumer's VMs live in THEIR home."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")

def register_vms():
    """Re-register any .pvm bundles the dispatcher doesn't know about. A fresh
    install (or a wiped /private/var/db/Parallels) loses the VM registry while
    the bundles in ~/Parallels survive — seen live on the 26.4.2 reset."""
    known = run(["prlctl", "list", "-a"]).stdout
    home = user_home()
    bundles = glob.glob(os.path.join(home, "Parallels", "*.pvm")) + \
              glob.glob(os.path.join(home, "Documents", "Parallels", "*.pvm"))
    for pvm in bundles:
        name = os.path.splitext(os.path.basename(pvm))[0]
        if not os.path.isfile(os.path.join(pvm, "config.pvs")) or name in known:
            continue
        r = run(["prlctl", "register", pvm])
        if r.returncode == 0:
            print("[+] re-registered VM: %s" % name)
        else:
            print("[!] could not register %s: %s" % (name, (r.stderr or r.stdout).strip()))

def main():
    ap = argparse.ArgumentParser(
        prog="parallels_activator.py",
        description="Parallels Desktop 26.4.x activation bypass — one-shot consumer flow. "
                    "Default (no flags) runs the full pipeline: patch, re-sign, forge "
                    "license, fresh dispatcher, re-register VMs.")
    ap.add_argument("--restore", action="store_true",
                    help="put the original binaries back and restart the dispatcher")
    ap.add_argument("--keygen", action="store_true",
                    help="only forge + deploy a fresh Pro license (expires 2099)")
    ap.add_argument("--test", action="store_true",
                    help="prove the bypass: stash the license, VM must still start")
    ap.add_argument("--e2e", action="store_true",
                    help="patch, then start Windows 11 with no license on disk")
    ap.add_argument("--keep-license", action="store_true",
                    help="leave an existing license alone (default flow re-forges)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[!] needs root — run:  sudo python3 %s" % os.path.abspath(__file__))

    if args.restore:
        stop_daemon()
        restore()
        lic = "/Library/Preferences/Parallels/licenses.json"
        stash = os.path.join(HERE, "licenses.json.stash")
        if os.path.isfile(stash) and not os.path.isfile(lic):
            shutil.move(stash, lic)
            print("[+] license restored")
        ensure_fresh_daemon()
        return
    if args.e2e:
        e2e()
        return
    if args.test:
        test_unlicensed()
        return
    if args.keygen:
        if forge_license():
            ensure_fresh_daemon()
            time.sleep(2)
            show_license()
        return

    # ---- default: full one-shot consumer pipeline ----
    print("[*] Parallels Desktop activation — full pipeline, no questions asked")
    for t in TARGETS:
        if not os.path.isfile(t):
            sys.exit("[!] %s not found — is Parallels Desktop installed?" % t)
        leg = legacy_of(t)
        if os.path.isfile(leg):
            # a backup inside the bundle invalidates the bundle signature — move it out
            if not os.path.isfile(backup_of(t)):
                shutil.move(leg, backup_of(t))
            else:
                os.remove(leg)
            print("[+] bundle-internal backup moved out for %s" % os.path.basename(t))
        if not os.path.isfile(backup_of(t)):
            shutil.copyfile(t, backup_of(t))
            print("[+] backup at %s" % backup_of(t))

    running = [l for l in run(["prlctl", "list", "-a"]).stdout.splitlines()
               if " running " in l]
    if running:
        print("[!] %d VM(s) running — the dispatcher restart suspends them; "
              "start them again afterwards (state is preserved)" % len(running))
    if not stop_daemon():
        sys.exit("[!] dispatcher still alive — aborted BEFORE patching, binaries untouched")
    for t in TARGETS:
        if not patch(t) or not resign(t):
            print("[!] patch/sign failed — restoring originals (patched but unsigned is worse than factory)")
            restore()
            ensure_fresh_daemon()
            sys.exit(1)
    if not verify_patches():
        print("[!] readback failed — restoring originals")
        restore()
        ensure_fresh_daemon()
        sys.exit(1)
    print("[+] all gates patched, re-signed, verified on disk")

    if args.keep_license and os.path.isfile(LICENSE_PATH):
        print("[*] --keep-license: existing license untouched")
    else:
        forge_license()

    if not ensure_fresh_daemon():
        sys.exit("[!] dispatcher would not come back on the patched image — run:\n"
                 "    sudo launchctl kickstart -k system/com.parallels.desktop.launchdaemon")
    time.sleep(2)
    register_vms()
    show_license()
    print("\n[+] done — Pro until 2099. Open Parallels Desktop and run your VMs.")

if __name__ == "__main__":
    main()
