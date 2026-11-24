"""Collecte de preuves (lecture seule) AVANT toute modification, cf. playbook section 3."""
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

from ..config import resolve
from ..models import ActionResult
from ..signatures import triage
from .base import Connector


class EvidenceConnector(Connector):
    """Cree un dossier de preuves horodate : incident complet, evenements echantillons,
    copie des journaux configures (log_files), et si la cible est l'hote local,
    le rapport `artex_triage.py host`. Un manifeste SHA-256 accompagne le tout."""
    supports = ("collect_evidence",)

    def run(self, action_type, params, incident, dry_run):
        base = resolve(self.soar_cfg, self.cfg.get("directory", "data/evidence"))
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        folder = os.path.join(base, f"{incident['id']}_{stamp}")
        log_files = list(self.cfg.get("log_files", []))
        if dry_run:
            return ActionResult(True, True, f"simulation : preuves dans {folder}", [], {"log_files": log_files})
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "incident.json"), "w") as f:
            json.dump(incident, f, indent=2, ensure_ascii=False)
        max_bytes = int(self.cfg.get("max_log_bytes", 50 * 1024 * 1024))
        for src in log_files:
            try:
                size = os.path.getsize(src)
                with open(src, "rb") as fin:
                    if size > max_bytes:
                        fin.seek(size - max_bytes)
                    data = fin.read()
                with open(os.path.join(folder, os.path.basename(src)), "wb") as fout:
                    fout.write(data)
            except OSError:
                continue
        local = {socket.gethostname(), "localhost"}
        if self.cfg.get("run_host_triage") and set(incident.get("targets") or []) & local:
            out = os.path.join(folder, "host_triage.json")
            argv = [sys.executable, triage.__file__, "host", "--json", out]
            for root in self.cfg.get("webroots", []):
                argv += ["--webroot", root]
            try:
                subprocess.run(argv, capture_output=True, timeout=600)
            except (OSError, subprocess.TimeoutExpired):
                pass
        manifest = {}
        for name in sorted(os.listdir(folder)):
            h = hashlib.sha256()
            with open(os.path.join(folder, name), "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            manifest[name] = h.hexdigest()
        with open(os.path.join(folder, "MANIFEST.sha256.json"), "w") as f:
            json.dump(manifest, f, indent=2)
        return ActionResult(True, False, f"preuves collectees : {folder}", [], {"path": folder, "files": manifest})
