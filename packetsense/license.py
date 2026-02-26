from pathlib import Path

LIC = Path("license.key")


def is_valid():
    try:
        if LIC.exists() and len(LIC.read_text().strip()) > 8:
            return True
        return False
    except:
        return False
