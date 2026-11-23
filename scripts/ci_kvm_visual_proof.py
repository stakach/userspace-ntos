"""Read a captured guest framebuffer for the command result required by the desktop gate."""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import subprocess


COMMAND = re.compile(r"(?im)^[ \t]*[a-z]:\\[^\r\n>]*>[ \t]*ver[ \t]*$")
RESULT = re.compile(r"(?im)^[ \t]*Microsoft Windows[ \t]*\[Version[ \t]+\d+(?:\.\d+)+\][ \t]*$")


@dataclass(frozen=True)
class VisualProof:
    passed: bool
    ocr_text: str = ""
    error: str = ""
    image_name: str = ""
    image_sha256: str = ""


def contains_ver_result(text):
    """Require the typed command and its response in that order in one framebuffer."""
    command = COMMAND.search(text)
    return command is not None and RESULT.search(text, command.end()) is not None


def prove_ver_result(image):
    """OCR the original PPM; any missing tool, image or result fails closed."""
    image = Path(image)
    if not image.is_file():
        return VisualProof(False, error=f"screenshot absent: {image}",
                           image_name=image.name)
    try:
        image_sha256 = hashlib.sha256(image.read_bytes()).hexdigest()
    except OSError as error:
        return VisualProof(False, error=f"cannot read screenshot: {error}",
                           image_name=image.name)
    try:
        result = subprocess.run(
            ["tesseract", str(image), "stdout", "-l", "eng", "--psm", "11"],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return VisualProof(False, error=f"OCR unavailable: {error}",
                           image_name=image.name,
                           image_sha256=image_sha256)
    if result.returncode != 0:
        return VisualProof(False, result.stdout,
                           f"OCR failed ({result.returncode}): {result.stderr.strip()}",
                           image.name, image_sha256)
    if not contains_ver_result(result.stdout):
        return VisualProof(False, result.stdout, "typed ver and response not both visible",
                           image.name, image_sha256)
    return VisualProof(True, result.stdout, image_name=image.name,
                       image_sha256=image_sha256)
