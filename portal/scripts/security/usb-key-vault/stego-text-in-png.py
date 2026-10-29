#!/usr/bin/env python3
"""Hide / reveal a short text secret in a PNG using LSB steganography.

Not cryptographic hiding by itself — anyone who knows the method can extract
unless you encrypt the payload first. Optional --password XOR-obfuscates the
bytes (better: encrypt offline, then embed ciphertext).

Examples:
  # Create a cover image and hide text
  python3 stego-text-in-png.py hide --out secret.png --text 'my passphrase'

  # Hide into an existing PNG (copies to --out)
  python3 stego-text-in-png.py hide --cover photo.png --out secret.png --text-file note.txt

  # Reveal
  python3 stego-text-in-png.py reveal --image secret.png
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import zlib
from pathlib import Path


MAGIC = b"SMSTEG1\0"  # 8 bytes


def _xor_stream(data: bytes, password: str) -> bytes:
    if not password:
        return data
    key = hashlib.sha256(password.encode("utf-8")).digest()
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _pack_payload(text: str, password: str) -> bytes:
    raw = text.encode("utf-8")
    body = _xor_stream(raw, password)
    # magic + u32 length + body
    return MAGIC + struct.pack(">I", len(body)) + body


def _unpack_payload(blob: bytes, password: str) -> str:
    if len(blob) < 12 or blob[:8] != MAGIC:
        raise ValueError("No stego payload found (wrong image or not an SMSTEG1 PNG).")
    (n,) = struct.unpack(">I", blob[8:12])
    body = blob[12 : 12 + n]
    if len(body) != n:
        raise ValueError("Truncated payload.")
    try:
        return _xor_stream(body, password).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Could not decode payload (wrong --password?)") from exc


# --- minimal PNG read/write (RGBA / RGB) ---

def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def write_solid_png(path: Path, width: int, height: int, rgb: tuple[int, int, int] = (32, 48, 72)) -> None:
    raw = bytearray()
    r, g, b = rgb
    for _y in range(height):
        raw.append(0)  # filter none
        for _x in range(width):
            raw.extend((r, g, b, 255))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)  # 8-bit RGBA
    png = b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + _png_chunk(b"IEND", b"")
    path.write_bytes(png)


def read_png_rgba(path: Path) -> tuple[int, int, bytearray]:
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Not a PNG file.")
    pos = 8
    width = height = None
    idat = bytearray()
    color_type = None
    bit_depth = None
    while pos < len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        tag = data[pos + 4 : pos + 8]
        chunk = data[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if tag == b"IHDR":
            width, height, bit_depth, color_type, *_ = struct.unpack(">IIBBBBB", chunk)
        elif tag == b"IDAT":
            idat.extend(chunk)
        elif tag == b"IEND":
            break
    if width is None or height is None:
        raise ValueError("Invalid PNG (no IHDR).")
    if bit_depth != 8 or color_type not in (2, 6):
        raise ValueError("Only 8-bit RGB or RGBA PNGs are supported.")
    raw = zlib.decompress(bytes(idat))
    bpp = 4 if color_type == 6 else 3
    stride = 1 + width * bpp
    pixels = bytearray()
    i = 0
    for _y in range(height):
        filt = raw[i]
        i += 1
        row = bytearray(raw[i : i + width * bpp])
        i += width * bpp
        if filt != 0:
            raise ValueError("Unsupported PNG filter (need filter 0). Re-export as uncompressed/simple PNG.")
        if bpp == 3:
            # expand to RGBA
            for x in range(width):
                o = x * 3
                pixels.extend((row[o], row[o + 1], row[o + 2], 255))
        else:
            pixels.extend(row)
    return width, height, pixels


def write_png_rgba(path: Path, width: int, height: int, pixels: bytes) -> None:
    raw = bytearray()
    row_bytes = width * 4
    for y in range(height):
        raw.append(0)
        o = y * row_bytes
        raw.extend(pixels[o : o + row_bytes])
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + _png_chunk(b"IEND", b"")
    )
    path.write_bytes(png)


def _embed_bits(pixels: bytearray, payload: bytes) -> None:
    bits = []
    for b in payload:
        for bit in range(7, -1, -1):
            bits.append((b >> bit) & 1)
    # capacity: use R,G,B channels only (skip alpha) = 3 bits per pixel
    capacity = (len(pixels) // 4) * 3
    if len(bits) > capacity:
        raise ValueError(f"Payload too large ({len(payload)} bytes); need larger image.")
    bi = 0
    for i in range(0, len(pixels), 4):
        for c in range(3):  # R,G,B
            if bi >= len(bits):
                return
            pixels[i + c] = (pixels[i + c] & 0xFE) | bits[bi]
            bi += 1


def _extract_bits(pixels: bytearray, n_bytes: int) -> bytes:
    need = n_bytes * 8
    bits = []
    for i in range(0, len(pixels), 4):
        for c in range(3):
            bits.append(pixels[i + c] & 1)
            if len(bits) >= need:
                break
        if len(bits) >= need:
            break
    out = bytearray()
    for i in range(0, need, 8):
        b = 0
        for bit in bits[i : i + 8]:
            b = (b << 1) | bit
        out.append(b)
    return bytes(out)


def cmd_hide(args: argparse.Namespace) -> int:
    if args.text is not None:
        text = args.text
    elif args.text_file:
        text = Path(args.text_file).read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()
    if not text:
        raise SystemExit("No text to hide.")

    out = Path(args.out)
    if args.cover:
        width, height, pixels = read_png_rgba(Path(args.cover))
    else:
        # Auto-size: ~3 bits/pixel → bytes capacity ≈ w*h*3/8; add margin
        need = len(_pack_payload(text, args.password or "")) + 64
        side = max(64, int((need * 8 / 3) ** 0.5) + 8)
        width = height = side
        write_solid_png(out, width, height)
        width, height, pixels = read_png_rgba(out)

    payload = _pack_payload(text, args.password or "")
    _embed_bits(pixels, payload)
    write_png_rgba(out, width, height, pixels)
    print(f"Wrote stego PNG: {out} ({width}x{height}, payload {len(payload)} bytes)")
    return 0


def cmd_reveal(args: argparse.Namespace) -> int:
    _w, _h, pixels = read_png_rgba(Path(args.image))
    # Read header first (12 bytes), then body
    header = _extract_bits(pixels, 12)
    if header[:8] != MAGIC:
        raise SystemExit("No SMSTEG1 payload in this PNG.")
    (n,) = struct.unpack(">I", header[8:12])
    blob = _extract_bits(pixels, 12 + n)
    text = _unpack_payload(blob, args.password or "")
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Hide/reveal text in a PNG (LSB steganography)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hide", help="Embed text into a PNG")
    h.add_argument("--cover", help="Existing PNG (RGB/RGBA, filter 0). If omitted, generate a solid cover.")
    h.add_argument("--out", required=True, help="Output PNG path")
    h.add_argument("--text", help="Text to hide (or use --text-file / stdin)")
    h.add_argument("--text-file", help="Read text from file")
    h.add_argument("--password", default="", help="Optional obfuscation password")
    h.set_defaults(func=cmd_hide)

    r = sub.add_parser("reveal", help="Extract text from a stego PNG")
    r.add_argument("--image", required=True, help="Stego PNG")
    r.add_argument("--password", default="", help="Password used at hide time")
    r.add_argument("--out", help="Write text to file instead of stdout")
    r.set_defaults(func=cmd_reveal)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
