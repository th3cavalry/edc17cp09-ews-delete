#!/usr/bin/env python3
"""
EWS Delete Patch for EDC17CP09 (HW 0281017487, SW 10375506116137U6A)

Patches FUN_00154e82 (EWS task) to always return 0x00 (authorized).
This disables the immobilizer gate without touching the config/OTP block.

Target: mpc_full.bin (2MB, 11/11 checksums valid)
Output: mpc_ews_deleted.bin (patched, checksums to be corrected)
"""

import sys
import struct

INPUT_FILE = 'mpc_full.bin'
OUTPUT_FILE = 'mpc_ews_deleted.bin'

# EWS task function: FUN_00154e82
# Patch offset in flash: 0x154eba
# Old bytes (14 bytes): df 20 0a 00 8b 10 20 02 82 5f ab 1f 80 20
#   0x154eba: df 20 0a 00  jeq d0, #2, #0x154ece
#   0x154ebe: 8b 10 20 02  ne d0, d0, #1
#   0x154ec2: 82 5f        mov d15, #5
#   0x154ec4: ab 1f 80 20  sel d2, d0, d15, #1
# New bytes (14 bytes): 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#   (7 NOPs, 2 bytes each)
# Effect: d2 remains 0 from mov d2, #0 at 0x154eb4, then ret at 0x154ec8

PATCH_OFFSET = 0x154eba
OLD_BYTES = bytes.fromhex('df 20 0a 00 8b 10 20 02 82 5f ab 1f 80 20'.replace(' ', ''))
NEW_BYTES = bytes(14)  # 14 zero bytes (7 NOPs)

def main():
    print(f"EWS Delete Patch for EDC17CP09")
    print(f"Input:  {INPUT_FILE}")
    print(f"Output: {OUTPUT_FILE}")
    print(f"Patch offset: 0x{PATCH_OFFSET:06x} ({PATCH_OFFSET} bytes)")
    print(f"Patch size:   {len(OLD_BYTES)} bytes")
    print()

    # Read input file
    with open(INPUT_FILE, 'rb') as f:
        data = bytearray(f.read())

    print(f"Input size: {len(data)} bytes (0x{len(data):x})")

    # Verify we're patching the right bytes
    current = data[PATCH_OFFSET:PATCH_OFFSET+len(OLD_BYTES)]
    if current != OLD_BYTES:
        print(f"ERROR: bytes at 0x{PATCH_OFFSET:06x} don't match expected!")
        print(f"  Expected: {OLD_BYTES.hex()}")
        print(f"  Found:    {current.hex()}")
        sys.exit(1)

    print(f"Original bytes verified ✓")
    print(f"  {OLD_BYTES.hex()}")
    print()

    # Apply patch
    data[PATCH_OFFSET:PATCH_OFFSET+len(NEW_BYTES)] = NEW_BYTES
    print(f"Patch applied:")
    print(f"  Old: {OLD_BYTES.hex()}")
    print(f"  New: {NEW_BYTES.hex()}")
    print()

    # Write output
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(data)

    print(f"Output written: {OUTPUT_FILE}")
    print()
    print("Next step: run checksum correction:")
    print(f"  .venv/bin/python medc17_checksum_tool.py --correct -o {OUTPUT_FILE} --fix-cvn {INPUT_FILE}")

if __name__ == '__main__':
    main()
