#!/usr/bin/env python3
"""从 unifont .hex 提取 ASCII + CJK 位图字形,生成本目录的 unifont_cjk.bin。

用法: python gen_unifont.py <input.hex> <output.bin>
"""
import sys

RANGES = [(0x20, 0x7E), (0x4E00, 0x9FFF)]


def main(src: str, dst: str) -> None:
    keep = set()
    for lo, hi in RANGES:
        keep.update(range(lo, hi + 1))

    glyphs = {}
    with open(src, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if ":" not in line:
                continue
            cp_s, _, hexdata = line.partition(":")
            try:
                cp = int(cp_s, 16)
            except ValueError:
                continue
            if cp not in keep:
                continue
            hexdata = hexdata.strip()
            bitmap = None
            if len(hexdata) == 64:
                # 全宽 16x16
                try:
                    bitmap = bytes.fromhex(hexdata)
                except ValueError:
                    continue
            elif len(hexdata) == 32:
                # 半宽 8x16:右半补零对齐到 16 宽,MSB 在左
                rows = bytearray(32)
                ok = True
                for r in range(16):
                    try:
                        rows[r * 2] = int(hexdata[r * 2 : r * 2 + 2], 16)
                    except ValueError:
                        ok = False
                        break
                bitmap = bytes(rows) if ok else None
            if bitmap:
                glyphs[cp] = bitmap

    out = bytearray()
    out += len(glyphs).to_bytes(4, "little")
    for cp in sorted(glyphs):
        out += cp.to_bytes(4, "little")
        out += glyphs[cp]
    with open(dst, "wb") as f:
        f.write(out)
    print(f"glyphs: {len(glyphs)}, bytes: {len(out)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
