#!/bin/bash
set -euo pipefail

DEVICE="${1:-localhost:5555}"
KO="/Users/prabhas/LibRizz/a64_hook/a64_hook.ko"
KO_PATCHED="/tmp/a64_hook_patched.ko"
DEVICE_KO="/data/local/tmp/a64_hook.ko"

echo "[*] Lowering kptr_restrict and reading kallsyms_lookup_name..."

KALLSYMS=$(adb -s "$DEVICE" shell 'su -c "
  echo 1 > /proc/sys/kernel/kptr_restrict
  grep -w kallsyms_lookup_name /proc/kallsyms | head -1
"')
echo "[*] kallsyms line: $KALLSYMS"
KALLSYMS_ADDR=$(echo "$KALLSYMS" | awk '{print $1}')
echo "[*] kallsyms_lookup_name address: $KALLSYMS_ADDR"

if [ -z "$KALLSYMS_ADDR" ] || [ "$KALLSYMS_ADDR" = "0000000000000000" ]; then
    echo "[!] Failed to read kallsyms_lookup_name"
    exit 1
fi

echo "[*] Patching sentinel in .ko..."
python3 << EOF
import sys, struct

ko_path = '$KO'
ko_patched = '$KO_PATCHED'
kallsyms_addr = '$KALLSYMS_ADDR'

with open(ko_path, 'rb') as f:
    data = f.read()

sentinel = struct.pack('<Q', 0xDEADBEEF00000001)
idx = data.find(sentinel)
if idx < 0:
    print('ERROR: sentinel not found in .ko')
    sys.exit(1)
print(f'Found sentinel at offset 0x{idx:x}')

addr = int(kallsyms_addr, 16)
addr_bytes = struct.pack('<Q', addr)
data = data[:idx] + addr_bytes + data[idx+8:]

with open(ko_patched, 'wb') as f:
    f.write(data)
print(f'Patched: {hex(addr)} -> {ko_patched}')
EOF

echo "[*] Pushing patched module to device..."
adb -s "$DEVICE" push "$KO_PATCHED" "$DEVICE_KO" > /dev/null

echo "[*] Loading module via finit_module..."
adb -s "$DEVICE" shell 'su -c "
  /data/local/tmp/flags_test /data/local/tmp/a64_hook.ko \"\" 3
"'

echo ""
echo "[*] DONE. Module loaded."
echo "[*] To activate:  adb -s $DEVICE shell su -c rmmod a64_hook"
echo "[*] To check:     adb -s $DEVICE shell su -c cat /proc/a64_hook"
echo "[*] To deactive:  adb -s $DEVICE shell su -c \"echo exit > /proc/a64_hook\" 2>/dev/null"
