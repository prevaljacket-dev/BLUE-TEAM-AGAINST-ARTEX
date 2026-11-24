"""Notification et ticketing (journal local, webhook Slack/Teams/Mattermost/TheHive, e-mail)."""
import json
import os
import smtplib
import time
import urllib.request
from email.message import EmailMessage

from ..config import resolve
from ..models import ActionResult
from .base import Connector


def summary(incident, params=None) -> str:
    params = params or {}
    who = incident.get("source_ip") or incident.get("key")
    tags = " [ARTEX confirme]" if incident.get("artex_confirmed") else ""
    if incident.get("status") == "authorized":
        tags += " [pentest autorise]"
    head = params.get("title") or "Incident ARTEX"
    return (f"{head} {incident['id']} {incident['severity']}{tags} : {who}, score {incident['score']}, "
            f"etape {incident['stage']}, cibles {', '.join(incident.get('targets') or ['?'])}. "
            f"Indicateurs : {', '.join(list(incident.get('indicators', {}))[:6])}")


class LogConnector(Connector):
    supports = ("notify", "open_ticket")

    def run(self, action_type, params, incident, dry_run):
        line = json.dumps({"ts": time.time(), "type": action_type, "message": summary(incident, params)},
                          ensure_ascii=False)
        path = self.cfg.get("path")
        if path and not dry_run:
            path = resolve(self.soar_cfg, path)
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "a") as f:
                f.write(line + "\n")
        print("[SOAR] " + summary(incident, params), flush=True)
        return ActionResult(True, dry_run, "notification journalisee")


class WebhookConnector(Connector):
    """POST JSON vers une URL que vous controlez. format: slack (champ text) | teams | raw."""
    supports = ("notify", "open_ticket")

    def run(self, action_type, params, incident, dry_run):
        url = self.cfg.get("url") or os.environ.get(self.cfg.get("url_env", ""), "")
        fmt = self.cfg.get("format", "slack")
        text = summary(incident, params)
        if fmt == "teams":
            body = {"@type": "MessageCard", "summary": "Incident ARTEX", "text": text}
        elif fmt == "raw":
            body = {"type": action_type, "incident": incident}
        else:
            body = {"text": text}
        if not url:
            return ActionResult(False, True, "webhook sans URL configuree (url ou url_env)")
        if dry_run:
            return ActionResult(True, True, f"simulation : POST {url}", [], {"body": body})
        headers = {"Content-Type": "application/json"}
        token = os.environ.get(self.cfg.get("token_env", ""), "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return ActionResult(True, False, f"webhook HTTP {r.status}")
        except OSError as e:
            return ActionResult(False, False, f"echec du webhook : {e}")


class EmailConnector(Connector):
    supports = ("notify",)

    def run(self, action_type, params, incident, dry_run):
        to = self.cfg.get("to") or []
        if not to:
            return ActionResult(False, True, "aucun destinataire (to)")
        msg = EmailMessage()
        msg["Subject"] = f"[SOAR ARTEX] {incident['severity']} {incident.get('source_ip') or incident['key']}"
        msg["From"] = self.cfg.get("from", "soar@localhost")
        msg["To"] = ", ".join(to)
        msg.set_content(summary(incident, params) + "\n\n" + json.dumps(incident, indent=2, ensure_ascii=False))
        if dry_run:
            return ActionResult(True, True, f"simulation : e-mail a {', '.join(to)}")
        try:
            with smtplib.SMTP(self.cfg.get("host", "localhost"), int(self.cfg.get("port", 25)), timeout=15) as s:
                if self.cfg.get("starttls"):
                    s.starttls()
                user = self.cfg.get("username")
                if user:
                    s.login(user, os.environ.get(self.cfg.get("password_env", "SOAR_SMTP_PASSWORD"), ""))
                s.send_message(msg)
        except OSError as e:
            return ActionResult(False, False, f"echec SMTP : {e}")
        return ActionResult(True, False, f"e-mail envoye a {', '.join(to)}")


class TicketFileConnector(Connector):
    """Un ticket JSON par incident (mis a jour a chaque declenchement). Pratique pour un
    import dans GLPI/Jira/TheHive ou comme trace d'audit."""
    supports = ("open_ticket",)

    def run(self, action_type, params, incident, dry_run):
        directory = resolve(self.soar_cfg, self.cfg.get("directory", "data/tickets"))
        path = os.path.join(directory, f"{incident['id']}.json")
        ticket = {"incident": incident["id"], "titre": summary(incident, params),
                  "priorite": incident["severity"], "statut": "ouvert",
                  "playbook": "playbook/PLAYBOOK.md", "maj": time.time(), "details": incident}
        if dry_run:
            return ActionResult(True, True, f"simulation : ticket {path}")
        os.makedirs(directory, exist_ok=True)
        with open(path, "w") as f:
            json.dump(ticket, f, indent=2, ensure_ascii=False)
        return ActionResult(True, False, f"ticket ecrit : {path}", [], {"path": path})
