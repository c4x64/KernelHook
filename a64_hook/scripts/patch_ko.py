#!/usr/bin/env python3
"""Patch sentinel value in a64_hook.ko with actual symbol address from System.map."""

import struct
import sys
import os

def main():
    if len(sys.argv) != 4:
        print("Usage: patch_ko.py <ko_path> <system_map_path> <symbol_name>")
        sys.exit(1)

    ko_path = sys.argv[1]
    map_path = sys.argv[2]
    sym_name = sys.argv[3]

    sentinel = 0xDEADBEEF00000001
    sentinel_bytes = struct.pack('<Q', sentinel)

    addr = None
    with open(map_path) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 3 and parts[2] == sym_name:
                addr = int(parts[0], 16)
                break

    if addr is None:
        print(f"Symbol '{sym_name}' not found in {map_path}")
        sys.exit(1)

    with open(ko_path, 'rb') as f:
        data = f.read()

    idx = data.find(sentinel_bytes)
    if idx < 0:
        print(f"Sentinel 0x{sentinel:016x} not found in {ko_path}")
        sys.exit(1)

    addr_bytes = struct.pack('<Q', addr)
    data = data[:idx] + addr_bytes + data[idx+8:]

    with open(ko_path, 'wb') as f:
        f.write(data)

    print(f"Patched {os.path.basename(ko_path)}: {sym_name} -> 0x{addr:016x} at offset 0x{idx:x}")

if __name__ == '__main__':
    main()
