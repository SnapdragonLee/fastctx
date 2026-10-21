"""Verify scheduler PAM boundaries in a disposable Linux CI machine, as root."""
import argparse
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import tempfile
import time


def run(*args, check=True, data=None, env=None, cwd=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=30, env=env, cwd=cwd)
    if check and result.returncode:
        raise RuntimeError(f"{args}: {result.returncode}\n{result.stdout}{result.stderr}")
    return result


def verify():
    if os.geteuid() != 0:
        raise RuntimeError("run only as root in a disposable test machine")
    for program in ("crontab", "at", "atq", "atrm", "loginctl", "setpriv", "systemd-run"):
        if not shutil.which(program):
            raise RuntimeError(f"required test dependency is missing: {program}")
    cron = "crond" if Path("/etc/redhat-release").exists() else "cron"
    run("systemctl", "start", cron, "atd", "polkit")
    root = Path(tempfile.mkdtemp(prefix="fastctx-pam-", dir="/var/tmp"))
    root.chmod(0o755)
    names = []
    since = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        for label in ("expired", "control"):
            name = "fxgp" + secrets.token_hex(4)
            directory = root / label
            run("useradd", "--system", "--user-group", "--no-create-home", "--no-log-init", "--shell", "/sbin/nologin",
                "--password", "!", "--home-dir", str(directory), "--expiredate", "1" if label == "expired" else "", name)
            names.append(name)
            # useradd --system can discard account ageing options. Match the
            # guardian's explicit usermod transition and inspect the actual field.
            run("usermod", "--expiredate", "1" if label == "expired" else "", name)
            expiry = run("getent", "shadow", name).stdout.split(":")[7]
            if expiry != ("1" if label == "expired" else ""):
                raise RuntimeError(f"the test account's expiry differs: {label} {expiry!r}")
            user = pwd.getpwnam(name)
            directory.mkdir(mode=0o700)
            os.chown(directory, user.pw_uid, user.pw_gid)
            prefix = ("setpriv", f"--reuid={user.pw_uid}", f"--regid={user.pw_gid}", "--clear-groups")
            environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(directory), "USER": name,
                           "LOGNAME": name, "SHELL": "/bin/bash", "XDG_RUNTIME_DIR": f"/run/user/{user.pw_uid}"}
            # Install through the actual account first. A pre-existing table
            # must also be rejected after expiry, so root restores it if needed.
            table = f"* * * * * /usr/bin/id > {directory}/cron\n"
            submitted = run(*prefix, "crontab", "-", data=table, env=environment, check=False)
            if submitted.returncode:
                run("crontab", "-u", name, "-", data=table)
            at = run(*prefix, "at", "now", data=f"/usr/bin/id > {directory}/at\n", env=environment, cwd=directory, check=False)
            linger = run(*prefix, "loginctl", "enable-linger", name, env=environment, check=False)
            print(json.dumps({"account": name, "trial": label, "uid": user.pw_uid, "shadow_expiry": expiry,
                              "crontab": [submitted.returncode, submitted.stderr], "at": [at.returncode, at.stderr],
                              "linger": [linger.returncode, linger.stdout, linger.stderr]}), flush=True)
            if label == "control" and (submitted.returncode or at.returncode or linger.returncode):
                raise RuntimeError("the non-expired scheduler control could not be submitted")
        deadline = time.monotonic() + 95
        while time.monotonic() < deadline:
            if all((root / "control" / item).exists() for item in ("cron", "at")):
                break
            time.sleep(1)
        for label, name in zip(("expired", "control"), names):
            user = pwd.getpwnam(name)
            prefix = ("setpriv", f"--reuid={user.pw_uid}", f"--regid={user.pw_gid}", "--clear-groups")
            directory = root / label
            environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(directory),
                           "XDG_RUNTIME_DIR": f"/run/user/{user.pw_uid}"}
            transient = run(*prefix, "systemd-run", "--user", "--wait", "/bin/sh", "-c",
                            f"/usr/bin/id > {directory}/systemd", env=environment, check=False)
            state = run("systemctl", "show", f"user@{user.pw_uid}.service", "-p", "ExecMainStatus", "-p", "ActiveState").stdout
            observed = {kind: (directory / kind).exists() for kind in ("cron", "at", "systemd")}
            print(json.dumps({"trial": label, "observed": observed, "user_manager": state,
                              "systemd_run": [transient.returncode, transient.stdout, transient.stderr]}), flush=True)
            if label == "expired" and (any(observed.values()) or transient.returncode == 0):
                raise RuntimeError("the expired account escaped through a scheduler")
            if label == "control" and not all(observed.values()):
                raise RuntimeError("the non-expired positive control did not run every scheduler")
            if label == "expired" and "ExecMainStatus=224" not in state:
                raise RuntimeError("linger was not proven to reach and fail PAM")
        log = run("journalctl", "--no-pager", "--since", since, "-u", cron, "-u", "atd",
                  "-u", f"user@{pwd.getpwnam(names[0]).pw_uid}.service").stdout
        print(log, flush=True)
        print("PASS expired PAM blocks cron, at, and self-enabled user services; all controls ran", flush=True)
    finally:
        for name in names:
            uid = pwd.getpwnam(name).pw_uid
            run("loginctl", "disable-linger", name, check=False)
            run("systemctl", "stop", f"user@{uid}.service", check=False)
            run("crontab", "-u", name, "-r", check=False)
            for line in run("atq").stdout.splitlines():
                fields = line.split()
                if fields and fields[-1] == name:
                    run("atrm", fields[0])
            run("userdel", name)
        shutil.rmtree(root)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    verify()
