"""Ligne de commande : serve | replay | ship."""
import argparse
import json
import os
import sys
import time
import urllib.request

from .config import load_config


def cmd_serve(args):
    import uvicorn
    from .api import create_app
    cfg = load_config(args.config)
    uvicorn.run(create_app(cfg), host=args.host, port=args.port, log_level="info")


def cmd_replay(args):
    """Rejoue des journaux hors ligne (base en memoire par defaut) et affiche le resultat."""
    from .engine import Engine
    from .parsers import parse_access_log, parse_suricata, parse_triage_host, parse_triage_logs
    from .store import Store
    cfg = load_config(args.config)
    if args.enforce:
        print("refus : replay est toujours en dry-run", file=sys.stderr)
        return 1
    cfg["mode"] = "dry_run"
    cfg["_force_dry_run"] = True  # aucun effet de bord, meme pour les connecteurs locaux
    engine = Engine(cfg, Store(args.db or ":memory:"))
    for path in args.files:
        with open(path, errors="replace") as f:
            if args.format == "access":
                engine.ingest(parse_access_log(f, sensor="replay", target=args.target))
            elif args.format == "eve":
                engine.ingest(parse_suricata(f))
            else:
                rep = json.load(f)
                engine.ingest(parse_triage_logs(rep) if "sources_suspectes" in rep else parse_triage_host(rep))
    incs = engine.store.list_incidents()
    out = []
    for inc in incs:
        inc["actions"] = engine.store.list_actions(incident_id=inc["id"])
        out.append(inc)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"== {len(incs)} incident(s), mode {cfg['mode']} ==")
    for inc in out:
        tag = " ARTEX" if inc["artex_confirmed"] else ""
        print(f"\n[{inc['severity']}{tag}] {inc['id']} {inc.get('source_ip') or inc['key']} score={inc['score']} "
              f"etape={inc['stage']} statut={inc['status']} evenements={inc['events']}")
        for label, n in list(inc["indicators"].items())[:12]:
            print(f"   - {label} ({n})")
        for a in sorted(inc["actions"], key=lambda a: a["created"]):
            det = (a.get("result") or {}).get("detail", "")
            cmds = (a.get("result") or {}).get("commands") or []
            print(f"   > {a['playbook']}: {a['type']} via {a['connector']} -> {a['status']} ({det})")
            for c in cmds:
                print("       $ " + " ".join(c))
    return 2 if any(i["severity"] in ("P1", "P2") for i in incs) else 0


def _post(url, key, path, body, ctype):
    req = urllib.request.Request(url.rstrip("/") + path, data=body, method="POST",
                                 headers={"X-API-Key": key, "Content-Type": ctype, "X-SOAR-User": "shipper"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def cmd_ship(args):
    """Agent leger : suit un fichier (comme tail -F) et envoie les nouvelles lignes au SOAR."""
    key = args.api_key or os.environ.get("SOAR_API_KEY", "")
    path = {"access": "/api/v1/ingest/access-log", "eve": "/api/v1/ingest/suricata"}[args.format]
    if args.target:
        path += "?target=" + urllib.request.quote(args.target)
    pos, inode = 0, None
    if not args.from_start and os.path.exists(args.file):
        pos = os.path.getsize(args.file)
    buf = []
    last_flush = time.time()
    while True:
        try:
            st = os.stat(args.file)
            if inode is not None and (st.st_ino != inode or st.st_size < pos):
                pos = 0  # rotation du journal
            inode = st.st_ino
            with open(args.file, errors="replace") as f:
                f.seek(pos)
                for line in f:
                    buf.append(line)
                pos = f.tell()
        except FileNotFoundError:
            pass
        if buf and (len(buf) >= args.batch or time.time() - last_flush >= args.interval):
            try:
                res = _post(args.url, key, path, "".join(buf).encode(), "text/plain")
                if res.get("incidents"):
                    print(f"[ship] {len(buf)} lignes -> incidents {res['incidents']}", flush=True)
                buf = []
            except OSError as e:
                print(f"[ship] envoi impossible ({e}), nouvel essai", file=sys.stderr, flush=True)
                buf = buf[-50000:]
            last_flush = time.time()
        if args.once:
            return 0
        time.sleep(1)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="artex-soar", description="SOAR defensif face a ARTEX")
    ap.add_argument("--config", default=os.environ.get("SOAR_CONFIG", "config/soar.yml"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("serve", help="lancer l'API et le tableau de bord")
    sp.add_argument("--host", default=os.environ.get("SOAR_HOST", "127.0.0.1"))
    sp.add_argument("--port", type=int, default=int(os.environ.get("SOAR_PORT", "8080")))

    rp = sub.add_parser("replay", help="rejouer des journaux hors ligne (toujours en dry-run)")
    rp.add_argument("files", nargs="+")
    rp.add_argument("--format", choices=["access", "eve", "triage"], default="access")
    rp.add_argument("--target", help="nom du serveur qui a produit le journal (ex. web01)")
    rp.add_argument("--db", help="base SQLite (defaut : en memoire)")
    rp.add_argument("--json", help="ecrire les incidents en JSON")
    rp.add_argument("--enforce", action="store_true", help=argparse.SUPPRESS)

    hp = sub.add_parser("ship", help="suivre un journal et l'envoyer a l'API")
    hp.add_argument("file")
    hp.add_argument("--url", default=os.environ.get("SOAR_URL", "http://127.0.0.1:8080"))
    hp.add_argument("--api-key")
    hp.add_argument("--format", choices=["access", "eve"], default="access")
    hp.add_argument("--target", help="nom du serveur (ex. web01)")
    hp.add_argument("--batch", type=int, default=500)
    hp.add_argument("--interval", type=float, default=5.0)
    hp.add_argument("--from-start", action="store_true")
    hp.add_argument("--once", action="store_true", help=argparse.SUPPRESS)

    args = ap.parse_args(argv)
    return {"serve": cmd_serve, "replay": cmd_replay, "ship": cmd_ship}[args.cmd](args) or 0


if __name__ == "__main__":
    sys.exit(main())
