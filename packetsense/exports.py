import zipfile
import tempfile
import json
from pathlib import Path

ALERTS_FILE = Path("data/alerts.jsonl")
ALERTS_FILE.parent.mkdir(exist_ok=True)


def write_alert(alert_obj):
    with open(ALERTS_FILE, "a") as fh:
        fh.write(json.dumps(alert_obj) + "\n")


def export_zip(named_files):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(tmp.name, "w") as z:
        for fname, data in named_files.items():
            z.writestr(fname, data)
    return tmp.name
