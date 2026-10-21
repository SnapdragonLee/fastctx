"""Two ordinary macOS accounts must not read each other's process arguments."""
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import secrets
import subprocess
import sys
import time


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=30)
    if check and result.returncode:
        raise RuntimeError(f"{args}: {result.stdout}{result.stderr}")
    return result


def reader(pid, marker, expected):
    ps = run("/bin/ps", "-ww", "-p", str(pid), "-o", "command=", check=False)
    libc = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2
    data = ctypes.create_string_buffer(1024 * 1024)
    size = ctypes.c_size_t(len(data))
    result = libc.sysctl(mib, 3, data, ctypes.byref(size), None, 0)
    code = ctypes.get_errno()
    print(json.dumps({"reader_uid": os.getuid(), "expected": expected, "ps": [ps.returncode, ps.stdout, ps.stderr],
                      "sysctl": [result, errno.errorcode.get(code, code), size.value]}), flush=True)
    seen = marker in ps.stdout or marker.encode() in data.raw[:size.value]
    if expected == "visible":
        # The same probe, run by the process's own account, must succeed;
        # otherwise a refusal below would prove nothing about the boundary.
        if result != 0 or not seen:
            raise RuntimeError("the process's own account could not read its arguments through KERN_PROCARGS2")
        return
    if seen:
        raise RuntimeError("another ordinary account read the private arguments")
    if result != -1:
        raise RuntimeError("KERN_PROCARGS2 was not refused by the OS")


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "read":
        reader(int(sys.argv[2]), sys.argv[3], sys.argv[4])
        return
    if sys.platform != "darwin" or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("run as root only on a disposable macOS GitHub runner")
    names = []
    victim = None
    marker = "private-argument-" + secrets.token_hex(16)
    used = {entry.pw_uid for entry in pwd.getpwall()}
    ids = [uid for uid in range(410, 499) if uid not in used][:2]
    if len(ids) != 2:
        raise RuntimeError("no unused test account IDs")
    try:
        for uid in ids:
            name = "fxg" + secrets.token_hex(5)
            record = "/Users/" + name
            run("dscl", ".", "-create", record)
            names.append(name)
            for key, value in (("UniqueID", str(uid)), ("PrimaryGroupID", "20"), ("NFSHomeDirectory", "/var/empty"),
                               ("UserShell", "/usr/bin/false"), ("IsHidden", "1"), ("Password", "*")):
                run("dscl", ".", "-create", record, key, value)
        victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(180)", marker],
                                  user=ids[0], group=20, extra_groups=[], cwd="/", stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(.2)
        if marker not in run("/bin/ps", "-ww", "-p", str(victim.pid), "-o", "command=").stdout:
            raise RuntimeError("positive control did not observe the private argument")
        probe = str(Path(__file__).resolve())
        print(run("sudo", "-u", names[0], sys.executable, probe, "read", str(victim.pid), marker, "visible").stdout)
        print(run("sudo", "-u", names[1], sys.executable, probe, "read", str(victim.pid), marker, "refused").stdout)
        print("PASS macOS: owner and root read the fixture; a second ordinary account cannot", flush=True)
    finally:
        if victim is not None:
            victim.terminate()
            victim.wait(timeout=10)
        for name in names:
            run("dscl", ".", "-delete", "/Users/" + name)


if __name__ == "__main__":
    main()
