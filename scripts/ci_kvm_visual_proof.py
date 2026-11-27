"""Read a captured guest framebuffer for the command result required by the desktop gate."""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import subprocess

try:
    from .ci_kvm_ppm import crop_ppm
except ImportError:
    from ci_kvm_ppm import crop_ppm


OCR_PUNCT_PREFIX = r"[ \t]*[^\w\s]{0,3}[ \t]*"
COMMAND = re.compile(r"(?im)^" + OCR_PUNCT_PREFIX + r"[a-z]:\\[^\r\n>]*>[ \t]*ver[ \t]*$")
RESULT = re.compile(r"(?im)^[ \t]*Microsoft Windows[ \t]*\[Version[ \t]+\d+(?:\.\d+)+\][ \t]*$")
ATTRIB_COMMAND = re.compile(
    r"(?im)^" + OCR_PUNCT_PREFIX +
    r"(?P<directory>[a-z]:\\[^\r\n>]*)>[ \t]*attrib[ \t]+(?P<name>[a-z0-9._-]+)[ \t]*$"
)
ATTRIB_RESULT = re.compile(
    r"(?im)^[ \t]*(?P<flags>[a-z \t]{0,24})[ \t]+(?P<path>[a-z]:\\[^\r\n]+?)[ \t]*$"
)
ATTRIB_RETURNED = re.compile(
    r"(?im)^" + OCR_PUNCT_PREFIX + r"(?P<directory>[a-z]:\\[^\r\n>]*)>,?[ \t]*$"
)
NEXT_PROMPT = re.compile(r"(?im)^" + OCR_PUNCT_PREFIX + r"[a-z]:\\[^\r\n>]*>")
READY_TITLE = re.compile(r"(?im)^[^\w\r\n]{0,3}Command Prompt[ \t]*$")
# Sparse-text OCR may join up to three punctuation glyphs from adjacent desktop
# text to the prompt line, and read the block cursor as a trailing comma. Keep
# the drive-path token and line tail anchored so typed commands still fail.
READY_PROMPT = re.compile(r"(?im)^" + OCR_PUNCT_PREFIX + r"[a-z]:\\[^\r\n>]{1,128}>,?[ \t]*$")
START_PROGRAMS = re.compile(r"(?im)^" + OCR_PUNCT_PREFIX + r"All Programs[ \t]*$")
START_SEARCH_BOX = re.compile(r"(?im)^" + OCR_PUNCT_PREFIX +
                              r"[Il]?Search programs and files[ \t]*$")
# Sparse OCR can read the shortcut's small icon as a numbered glyph ("2)").
# Keep the title anchored and limit that prefix so console text cannot pass.
SEARCH_RESULT_PREFIX = r"[ \t]*(?:[0-9]{1,2}[)\].][ \t]*)?[^\w\s]{0,3}[ \t]*"
SEARCH_COMMAND_PROMPT = re.compile(r"(?im)^" + SEARCH_RESULT_PREFIX + r"Command Prompt[ \t]*$")
SEARCH_MENU_SHUTDOWN = re.compile(r"(?im)^" + OCR_PUNCT_PREFIX + r"Shut down[ \t]*$")
# Pinned 1024x768 LiberNT Start edit interior. The full-frame sparse OCR has
# misread its tiny text; a doubled crop reads the exact query on saved frames.
SEARCH_QUERY_CROP = (17, 683, 210, 702)
# The top console input row and the next returned prompt row in the pinned
# 1024x768 FileBasic frame. Each crop is read from the original captured PPM.
CREATE_INPUT_CROP = (70, 216, 600, 243)
CREATE_PROMPT_CROP = (70, 250, 600, 274)
# Command, exact directory header, count row and returned prompt in the pinned
# 1024x768 console. Whole-frame sparse OCR can read the zero as "@ File(s)".
DIRECTORY_LIST_CROP = (70, 246, 500, 421)
# The lower console rows in the pinned FileBasic frame show the attrib query,
# its result and the returned prompt. Sparse full-frame OCR can split `.txt`.
ATTRIB_READBACK_CROP = (68, 426, 520, 510)
# Bottom input row of the pinned 1024x768 Command Prompt in the FileBasic
# frame. Sparse full-screen OCR can merge desktop glyphs into this row.
CHILD_PROMPT_CROP = (158, 558, 805, 582)
# OCR may attach the next prompt's first typed glyph to the child's stdout row.
# The result is still distinguishable from the echoed `cmd /c echo` command.
CHILD_STDOUT_LINE = re.compile(
    r"(?im)^(?:" + OCR_PUNCT_PREFIX + r"[a-z]:\\[^\r\n>]*>[a-z]?)?CHILD_STDOUT_OK[ \t]*$"
)
CREATE_COMMAND = re.compile(
    r"(?im)^" + OCR_PUNCT_PREFIX +
    r"(?P<directory>[a-z]:\\[^\r\n>]{1,128})>md basicproof,{0,2}[ \t]*$"
)
CREATE_RETURNED = re.compile(
    r"(?im)^" + OCR_PUNCT_PREFIX +
    r"(?P<directory>[a-z]:\\[^\r\n>]{1,128})>,?[ \t]*$"
)
DIR_COMMAND = re.compile(
    r"(?im)^" + OCR_PUNCT_PREFIX +
    r"(?P<directory>[a-z]:\\[^\r\n>]*)>[ \t]*dir[ \t]+basicproof[ \t]*$"
)
DIR_HEADER = re.compile(r"(?im)^[ \t]*Directory of (?P<path>[a-z]:\\[^\r\n]+?)[ \t]*$")
DIR_TOTAL = re.compile(r"(?im)^[ \t]*\d+[ \t]+File\(s\)")
ATTRIB_HELP_TAIL = re.compile(
    r"(?im)^Type ATTRIB without a parameter to display the attributes of all files\.[ \t]*$"
)


@dataclass(frozen=True)
class VisualProof:
    passed: bool
    ocr_text: str = ""
    error: str = ""
    image_name: str = ""
    image_sha256: str = ""
    fatal: bool = False


def contains_ver_result(text):
    """Require the typed command and its response in that order in one framebuffer."""
    command = COMMAND.search(text)
    return command is not None and RESULT.search(text, command.end()) is not None


def contains_readonly_attribute(text, name, *, readonly):
    """Match the last typed attrib query to its exact result in the same directory."""
    if not re.fullmatch(r"[a-z0-9._-]+", name, re.IGNORECASE):
        return False
    commands = [match for match in ATTRIB_COMMAND.finditer(text)
                if match.group("name").casefold() == name.casefold()]
    if not commands:
        return False
    command = commands[-1]
    directory = command.group("directory").rstrip("\\")
    expected_path = (directory + "\\" + name).casefold()
    tail = text[command.end():]
    returned = ATTRIB_RETURNED.search(tail)
    if (returned is None or
            returned.group("directory").rstrip("\\").casefold() != directory.casefold()):
        return False
    tail = tail[:returned.start()]
    for result in ATTRIB_RESULT.finditer(tail):
        if result.group("path").casefold() == expected_path:
            return ("r" in result.group("flags").casefold()) == readonly
    return False


def contains_ready_prompt(text):
    """Find a foreground Command Prompt title followed by a ready input prompt."""
    title = READY_TITLE.search(text)
    return title is not None and READY_PROMPT.search(text, title.end()) is not None


def contains_child_stdout_completion(text):
    """The child printed its marker and cmd returned to an empty input prompt."""
    marker = CHILD_STDOUT_LINE.search(text)
    return marker is not None and READY_PROMPT.search(text, marker.end()) is not None


def contains_basicproof_create_completion(text):
    """The exact mkdir command finished and returned to its empty input line."""
    commands = list(CREATE_COMMAND.finditer(text))
    if not commands:
        return False
    command = commands[-1]
    tail = text[command.end():]
    returned = CREATE_RETURNED.search(tail)
    if returned is None or returned.group("directory").casefold() != command.group("directory").casefold():
        return False
    return re.search(r"(?im)^\s*(?:Syntax error|A subdirectory or file .* already exists)",
                     tail[:returned.start()]) is None


def contains_basicproof_directory(text):
    """The requested directory was listed, not a missing parent entry."""
    commands = list(DIR_COMMAND.finditer(text))
    if not commands:
        return False
    command = commands[-1]
    expected = command.group("directory").rstrip("\\") + "\\basicproof"
    tail = text[command.end():]
    next_prompt = NEXT_PROMPT.search(tail)
    if next_prompt:
        tail = tail[:next_prompt.start()]
    if re.search(r"(?im)^[ \t]*File not found[ \t]*$", tail):
        return False
    return any(header.group("path").casefold() == expected.casefold() and
               DIR_TOTAL.search(tail, header.end()) is not None
               for header in DIR_HEADER.finditer(tail))


def contains_attrib_help_completion(text):
    """The help command reached its final line and returned to cmd."""
    tail = ATTRIB_HELP_TAIL.search(text)
    return tail is not None and READY_PROMPT.search(text, tail.end()) is not None


def contains_start_menu_search_box(text):
    """Require the visible Start menu before targeting its search field."""
    return START_PROGRAMS.search(text) is not None and START_SEARCH_BOX.search(text) is not None


def contains_command_prompt_search_result(text):
    """Require a shortcut result in the Start menu, not an old console title."""
    return (SEARCH_COMMAND_PROMPT.search(text) is not None and
            SEARCH_MENU_SHUTDOWN.search(text) is not None)


def _prove_image(image, predicate, missing):
    """OCR the original PPM and retain its hash and transcript on every outcome."""
    image = Path(image)
    if not image.is_file():
        return VisualProof(False, error=f"screenshot absent: {image}",
                           image_name=image.name, fatal=True)
    try:
        frame = image.read_bytes()
        image_sha256 = hashlib.sha256(frame).hexdigest()
    except OSError as error:
        return VisualProof(False, error=f"cannot read screenshot: {error}",
                           image_name=image.name, fatal=True)
    try:
        result = subprocess.run(
            ["tesseract", "stdin", "stdout", "-l", "eng", "--psm", "11"],
            input=frame, capture_output=True, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return VisualProof(False, error=f"OCR unavailable: {error}",
                           image_name=image.name,
                           image_sha256=image_sha256, fatal=True)
    transcript = (result.stdout.decode("utf-8", errors="replace")
                  if isinstance(result.stdout, bytes) else result.stdout)
    stderr = (result.stderr.decode("utf-8", errors="replace")
              if isinstance(result.stderr, bytes) else result.stderr)
    if result.returncode != 0:
        return VisualProof(False, transcript,
                           f"OCR failed ({result.returncode}): {stderr.strip()}",
                           image.name, image_sha256, fatal=True)
    if not predicate(transcript):
        return VisualProof(False, transcript, missing,
                           image.name, image_sha256)
    return VisualProof(True, transcript, image_name=image.name,
                       image_sha256=image_sha256)


def prove_ready_prompt(image):
    """Require a visible ready Command Prompt before any test command is typed."""
    return _prove_image(image, contains_ready_prompt, "ready Command Prompt not visible")


def prove_basicproof_create_input(image):
    """Verify the exact foreground line before sending its Return key."""
    result = _prove_image(image,
                          lambda text: READY_TITLE.search(text) is not None
                          and CREATE_COMMAND.search(text) is not None
                          and not contains_basicproof_create_completion(text),
                          "exact md basicproof input line not visible")
    if not result.passed:
        return result
    try:
        line_frame = crop_ppm(image, *CREATE_INPUT_CROP)
        line_ocr = subprocess.run(
            ["tesseract", "stdin", "stdout", "-l", "eng", "--psm", "7"],
            input=line_frame, capture_output=True, timeout=20, check=False,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return VisualProof(False, result.ocr_text, f"create input OCR unavailable: {error}",
                           result.image_name, result.image_sha256, fatal=True)
    line = line_ocr.stdout.decode("utf-8", errors="replace").strip()
    transcript = result.ocr_text + "\ncreate input crop: " + line
    if line_ocr.returncode != 0:
        detail = line_ocr.stderr.decode("utf-8", errors="replace").strip()
        return VisualProof(False, transcript,
                           f"create input OCR failed ({line_ocr.returncode}): {detail}",
                           result.image_name, result.image_sha256, fatal=True)
    if re.fullmatch(r"(?i)[a-z]:\\[^\r\n>]{1,128}>md basicproof,{0,2}", line) is None:
        return VisualProof(False, transcript, "exact md basicproof input line not visible",
                           result.image_name, result.image_sha256)
    return VisualProof(True, transcript, image_name=result.image_name,
                       image_sha256=result.image_sha256)


def prove_basicproof_create_completion(image):
    """After Return, require a new empty prompt before another command."""
    result = _prove_image(image, contains_basicproof_create_completion,
                          "md basicproof did not return to an empty prompt")
    if result.fatal:
        return result
    commands = list(CREATE_COMMAND.finditer(result.ocr_text))
    if not commands:
        return result
    command = commands[-1]
    if re.search(
        r"(?im)^\s*(?:Syntax error|A subdirectory or file .* already exists)",
        result.ocr_text[command.end():],
    ) is not None:
        return VisualProof(False, result.ocr_text, "md basicproof reported an error",
                           result.image_name, result.image_sha256)
    try:
        prompt_frame = crop_ppm(image, *CREATE_PROMPT_CROP)
        prompt_ocr = subprocess.run(
            ["tesseract", "stdin", "stdout", "-l", "eng", "--psm", "7"],
            input=prompt_frame, capture_output=True, timeout=20, check=False,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return VisualProof(False, result.ocr_text, f"create prompt OCR unavailable: {error}",
                           result.image_name, result.image_sha256, fatal=True)
    prompt = prompt_ocr.stdout.decode("utf-8", errors="replace").strip()
    transcript = result.ocr_text + "\ncreate prompt crop: " + prompt
    if prompt_ocr.returncode != 0:
        detail = prompt_ocr.stderr.decode("utf-8", errors="replace").strip()
        return VisualProof(False, transcript,
                           f"create prompt OCR failed ({prompt_ocr.returncode}): {detail}",
                           result.image_name, result.image_sha256, fatal=True)
    match = re.fullmatch(r"(?i)(?P<directory>[a-z]:\\[^\r\n>]{1,128})>,?", prompt)
    if match is None or match.group("directory").casefold() != command.group("directory").casefold():
        return VisualProof(False, transcript, "md basicproof did not return to an empty prompt",
                           result.image_name, result.image_sha256)
    return VisualProof(True, transcript, image_name=result.image_name,
                       image_sha256=result.image_sha256)


def prove_child_stdout_completion(image):
    result = _prove_image(image, contains_child_stdout_completion,
                          "child stdout marker and returned prompt not visible")
    if result.passed or result.fatal or CHILD_STDOUT_LINE.search(result.ocr_text) is None:
        return result
    try:
        prompt_frame = crop_ppm(image, *CHILD_PROMPT_CROP)
        prompt_ocr = subprocess.run(
            ["tesseract", "stdin", "stdout", "-l", "eng", "--psm", "7"],
            input=prompt_frame, capture_output=True, timeout=20, check=False,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return VisualProof(False, result.ocr_text, f"child prompt OCR unavailable: {error}",
                           result.image_name, result.image_sha256, fatal=True)
    prompt = prompt_ocr.stdout.decode("utf-8", errors="replace").strip()
    transcript = result.ocr_text + "\nchild prompt crop: " + prompt
    if prompt_ocr.returncode != 0:
        detail = prompt_ocr.stderr.decode("utf-8", errors="replace").strip()
        return VisualProof(False, transcript,
                           f"child prompt OCR failed ({prompt_ocr.returncode}): {detail}",
                           result.image_name, result.image_sha256, fatal=True)
    if re.fullmatch(r"(?i)[a-z]:\\[^\r\n>]{1,128}>", prompt) is None:
        return VisualProof(False, transcript, result.error,
                           result.image_name, result.image_sha256)
    return VisualProof(True, transcript, image_name=result.image_name,
                       image_sha256=result.image_sha256)


def prove_basicproof_directory(image):
    result = _prove_image(image, contains_basicproof_directory,
                          "basicproof directory listing not visible")
    if result.passed or result.fatal:
        return result
    try:
        frame = crop_ppm(image, *DIRECTORY_LIST_CROP)
        ocr = subprocess.run(
            ["tesseract", "stdin", "stdout", "-l", "eng", "--psm", "6"],
            input=frame, capture_output=True, timeout=20, check=False,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return VisualProof(False, result.ocr_text, f"directory crop OCR unavailable: {error}",
                           result.image_name, result.image_sha256, fatal=True)
    text = ocr.stdout.decode("utf-8", errors="replace")
    transcript = result.ocr_text + "\ndirectory crop: " + text
    if ocr.returncode != 0:
        detail = ocr.stderr.decode("utf-8", errors="replace").strip()
        return VisualProof(False, transcript,
                           f"directory crop OCR failed ({ocr.returncode}): {detail}",
                           result.image_name, result.image_sha256, fatal=True)
    if not contains_basicproof_directory(text) or READY_PROMPT.search(text) is None:
        return VisualProof(False, transcript, result.error,
                           result.image_name, result.image_sha256)
    return VisualProof(True, transcript, image_name=result.image_name,
                       image_sha256=result.image_sha256)


def prove_attrib_help_completion(image):
    return _prove_image(image, contains_attrib_help_completion,
                        "attrib help tail and returned prompt not visible")


def prove_start_menu_search_box(image):
    """Require the original frame to show the Start menu search control."""
    return _prove_image(image, contains_start_menu_search_box,
                        "Start menu search box not visible")


def prove_command_prompt_search_result(image):
    """Require the visible result and exact typed query in the original frame."""
    result = _prove_image(image, contains_command_prompt_search_result,
                          "Command Prompt search result not visible")
    if not result.passed:
        return result
    try:
        query_frame = crop_ppm(image, *SEARCH_QUERY_CROP, scale=2)
        query = subprocess.run(
            ["tesseract", "stdin", "stdout", "-l", "eng", "--psm", "7"],
            input=query_frame, capture_output=True,
            timeout=20, check=False,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return VisualProof(False, result.ocr_text, f"search query OCR unavailable: {error}",
                           result.image_name, result.image_sha256, fatal=True)
    query_text = query.stdout.decode("utf-8", errors="replace").strip()
    transcript = result.ocr_text + "\nsearch query crop: " + query_text
    if query.returncode != 0:
        detail = query.stderr.decode("utf-8", errors="replace").strip()
        return VisualProof(False, transcript,
                           f"search query OCR failed ({query.returncode}): {detail}",
                           result.image_name, result.image_sha256, fatal=True)
    if query_text.casefold() != "command":
        return VisualProof(False, transcript, "exact command query not visible",
                           result.image_name, result.image_sha256)
    return VisualProof(True, transcript, image_name=result.image_name,
                       image_sha256=result.image_sha256)


def prove_ver_result(image):
    """Require the typed command and its response in the final original PPM."""
    return _prove_image(image, contains_ver_result,
                        "typed ver and response not both visible")


def prove_readonly_attribute(image, name, *, readonly):
    """Require the captured attrib query and its exact before/after state."""
    state = "present" if readonly else "absent"
    result = _prove_image(image,
                          lambda text: contains_readonly_attribute(text, name, readonly=readonly),
                          f"exact {name} attrib readback with read-only {state} not visible")
    if result.passed or result.fatal:
        return result
    try:
        frame = crop_ppm(image, *ATTRIB_READBACK_CROP, scale=2)
        ocr = subprocess.run(
            ["tesseract", "stdin", "stdout", "-l", "eng", "--psm", "6"],
            input=frame, capture_output=True, timeout=20, check=False,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return VisualProof(False, result.ocr_text, f"attrib crop OCR unavailable: {error}",
                           result.image_name, result.image_sha256, fatal=True)
    text = ocr.stdout.decode("utf-8", errors="replace")
    transcript = result.ocr_text + "\nattrib crop: " + text
    if ocr.returncode != 0:
        detail = ocr.stderr.decode("utf-8", errors="replace").strip()
        return VisualProof(False, transcript,
                           f"attrib crop OCR failed ({ocr.returncode}): {detail}",
                           result.image_name, result.image_sha256, fatal=True)
    if not contains_readonly_attribute(text, name, readonly=readonly):
        return VisualProof(False, transcript, result.error,
                           result.image_name, result.image_sha256)
    return VisualProof(True, transcript, image_name=result.image_name,
                       image_sha256=result.image_sha256)
