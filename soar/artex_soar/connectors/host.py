"""Isolation d'un serveur de VOTRE inventaire via une commande que vous fournissez."""
import re

from ..models import ActionResult
from .base import Connector

PLACEHOLDER = re.compile(r"\{(host|incident_id)\}")


class CommandConnector(Connector):
    """Lance une commande locale (argv, sans shell) avec les variables {host} et {incident_id}.

    Exemples : un playbook Ansible qui applique une politique reseau de quarantaine, un appel a
    l'API de votre EDR, un script qui deplace la VM dans un VLAN d'isolement.

        isolation:
          type: command
          argv: ["ansible-playbook", "/etc/soar/isolate.yml", "-l", "{host}"]
    """
    disruptive = True
    supports = ("isolate_host",)

    def run(self, action_type, params, incident, dry_run):
        argv = self.cfg.get("argv")
        if not argv:
            return ActionResult(False, dry_run, "connecteur 'command' sans argv configure")
        values = {"host": params.get("host", ""), "incident_id": incident["id"]}
        cmd = [PLACEHOLDER.sub(lambda m: values[m.group(1)], str(a)) for a in argv]
        return self.exec_commands([cmd], dry_run, timeout=int(self.cfg.get("timeout", 120)))
