"""Liste de blocage sous forme de fichier (nginx `deny`, liste d'IP pour WAF/HAProxy...)."""
import json
import os
import time

from ..config import resolve
from ..guard import valid_ip
from ..models import ActionResult
from .base import Connector


class BlocklistFileConnector(Connector):
    """Maintient un fichier de blocage regenere a chaque ajout (les entrees expirees sont purgees).

    format: nginx  -> "deny 198.51.100.66;"  (a inclure dans un bloc server/http)
    format: plain  -> une IP par ligne (HAProxy, ModSecurity, WAF...)
    reload_command: commande optionnelle apres ecriture, ex. ["nginx", "-s", "reload"]
    """
    disruptive = True
    supports = ("block_ip",)

    def run(self, action_type, params, incident, dry_run):
        ip = incident.get("source_ip")
        if not valid_ip(ip):
            return ActionResult(False, dry_run, f"IP invalide : {ip!r}")
        path = resolve(self.soar_cfg, self.cfg.get("path", "data/blocklist.conf"))
        state_path = path + ".state.json"
        ttl = max(60, int(params.get("ttl", self.cfg.get("default_ttl", 86400))))
        now = time.time()
        try:
            with open(state_path) as f:
                state = json.load(f)
        except (OSError, ValueError):
            state = {}
        state = {k: v for k, v in state.items() if v["expires"] > now}
        state[ip] = {"expires": now + ttl, "incident": incident["id"]}
        fmt = self.cfg.get("format", "nginx")
        lines = ["# Genere par ARTEX SOAR - ne pas editer a la main"]
        for addr, meta in sorted(state.items()):
            exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(meta["expires"]))
            lines.append((f"deny {addr};" if fmt == "nginx" else addr) + f"  # expire {exp} {meta['incident']}")
        content = "\n".join(lines) + "\n"
        reload_cmd = self.cfg.get("reload_command")
        if dry_run:
            return ActionResult(True, True, f"simulation : {ip} serait ajoute a {path}",
                                [reload_cmd] if reload_cmd else [], {"ip": ip, "preview": content[-500:]})
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(content)
        os.replace(tmp, path)
        with open(state_path, "w") as f:
            json.dump(state, f)
        if reload_cmd:
            res = self.exec_commands([list(reload_cmd)], False)
            res.detail = f"{ip} ajoute a {path} ; " + res.detail
            res.data["ip"] = ip
            return res
        return ActionResult(True, False, f"{ip} ajoute a {path}", [], {"ip": ip})
