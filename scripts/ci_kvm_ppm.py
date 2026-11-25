"""Read and crop original QMP P6 framebuffers for bounded visual checks."""

from pathlib import Path


def read_ppm(path):
    data = Path(path).read_bytes()
    header = data.split(b"\n", 3)
    if len(header) != 4 or header[0] != b"P6" or header[2] != b"255":
        raise ValueError(f"unsupported QMP PPM: {path}")
    try:
        width, height = (int(value) for value in header[1].split())
    except (TypeError, ValueError) as error:
        raise ValueError(f"invalid QMP PPM dimensions: {path}") from error
    pixels = header[3]
    if width <= 0 or height <= 0 or len(pixels) != width * height * 3:
        raise ValueError(f"invalid QMP PPM pixel data: {path}")
    return width, height, pixels


def crop_ppm(path, left, top, right, bottom, scale=1):
    """Return a P6 crop using exact source pixels and integer nearest-neighbor scale."""
    width, height, pixels = read_ppm(path)
    if not (0 <= left < right <= width and 0 <= top < bottom <= height and
            isinstance(scale, int) and scale > 0):
        raise ValueError("PPM crop lies outside framebuffer")
    output = bytearray(f"P6\n{(right - left) * scale} {(bottom - top) * scale}\n255\n".encode())
    for y in range(top, bottom):
        row = bytearray()
        for x in range(left, right):
            offset = (y * width + x) * 3
            row.extend(pixels[offset:offset + 3] * scale)
        output.extend(row * scale)
    return bytes(output)
