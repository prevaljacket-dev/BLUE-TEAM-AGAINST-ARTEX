"""Interface commune des connecteurs d'action."""
import subprocess
from typing import Any, Dict, List

from ..models import ActionResult


class Connector:
    #: Un connecteur perturbateur (blocage, isolation) reste en simulation tant que
    #: le mode global vaut "dry_run" ou que son option dry_run vaut true.
    disruptive = False
    #: Types d'action pris en charge.
    supports: tuple = ()

    def __init__(self, name: str, cfg: Dict[str, Any], soar_cfg: Dict[str, Any]):
        self.name = name
        self.cfg = cfg
        self.soar_cfg = soar_cfg
        # Par defaut, un connecteur perturbateur est en dry-run sauf mention contraire explicite.
        self.dry_run = bool(cfg.get("dry_run", self.disruptive))

    def effective_dry_run(self) -> bool:
        if self.soar_cfg.get("_force_dry_run"):
            return True
        if not self.disruptive:
            return bool(self.cfg.get("dry_run", False))
        return self.soar_cfg.get("mode") != "enforce" or self.dry_run

    def run(self, action_type: str, params: Dict[str, Any], incident: Dict[str, Any],
            dry_run: bool) -> ActionResult:
        raise NotImplementedError

    @staticmethod
    def exec_commands(commands: List[List[str]], dry_run: bool, timeout: int = 30) -> ActionResult:
        """Execute des commandes (liste d'arguments, jamais via un shell)."""
        if dry_run:
            return ActionResult(True, True, "simulation : commandes non executees", commands)
        outputs = []
        for argv in commands:
            try:
                p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            except (OSError, subprocess.TimeoutExpired) as e:
                return ActionResult(False, False, f"echec de {argv[0]} : {e}", commands)
            outputs.append({"argv": argv, "rc": p.returncode, "stderr": p.stderr[-500:]})
            if p.returncode != 0:
                return ActionResult(False, False, f"{argv[0]} a renvoye {p.returncode} : {p.stderr.strip()[:300]}",
                                    commands, {"outputs": outputs})
        return ActionResult(True, False, "commandes executees", commands, {"outputs": outputs})
