"""Measure the guest cursor from two QMP framebuffer captures before clicking.

The comparison is restricted to a bounded region around the target. The first frame has the
cursor elsewhere; only pointer motion is allowed before the second frame. This
keeps the measurement independent of the guest's cursor artwork and theme.
"""

from dataclasses import dataclass
import hashlib
from pathlib import Path

DIFFERENCE_THRESHOLD = 90
TARGET_TOLERANCE = 3
SEARCH_RADIUS = 60


@dataclass(frozen=True)
class CursorProof:
    position: tuple | None
    image_name: str
    image_sha256: str


def _read_ppm(path):
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


def measure_cursor_hotspot(before, after, origin=(0, 0), search=None):
    """Return the top-left cursor hotspot from changed pixels, or None.

    ``origin`` maps a cropped recorded frame back to full-screen coordinates.
    Runtime captures use the full screen and a narrow ``search`` rectangle.
    """
    width, height, old = _read_ppm(before)
    new_width, new_height, new = _read_ppm(after)
    if (width, height) != (new_width, new_height):
        raise ValueError("cursor frame dimensions differ")
    left, top, right, bottom = search or (0, 0, width, height)
    if not (0 <= left < right <= width and 0 <= top < bottom <= height):
        raise ValueError("cursor search lies outside framebuffer")
    changed = []
    for y in range(top, bottom):
        for x in range(left, right):
            offset = (y * width + x) * 3
            if sum(abs(old[offset + channel] - new[offset + channel])
                   for channel in range(3)) > DIFFERENCE_THRESHOLD:
                changed.append((x, y))
    if len(changed) < 20:
        return None
    min_x = min(x for x, _ in changed)
    min_y = min(y for _, y in changed)
    max_x = max(x for x, _ in changed)
    max_y = max(y for _, y in changed)
    if max_x - min_x > 32 or max_y - min_y > 40:
        return None
    return min_x + origin[0], min_y + origin[1]


def cursor_is_at_target(position, target):
    """Accept only a measured cursor within a small target margin."""
    return (position is not None
            and abs(position[0] - target[0]) <= TARGET_TOLERANCE
            and abs(position[1] - target[1]) <= TARGET_TOLERANCE)


def prove_cursor_position(before, after, target):
    """Measure a cursor near a target and retain the original screenshot hash."""
    after = Path(after)
    width, height, _pixels = _read_ppm(after)
    left = max(0, target[0] - SEARCH_RADIUS)
    top = max(0, target[1] - SEARCH_RADIUS)
    right = min(width, target[0] + SEARCH_RADIUS + 1)
    bottom = min(height, target[1] + SEARCH_RADIUS + 1)
    position = measure_cursor_hotspot(before, after,
                                      search=(left, top, right, bottom))
    return CursorProof(position, after.name,
                       hashlib.sha256(after.read_bytes()).hexdigest())
