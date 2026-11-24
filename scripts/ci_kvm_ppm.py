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
