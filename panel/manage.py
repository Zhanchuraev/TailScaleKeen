import argparse, json, pathlib, subprocess, sys, os
from .core import Error


def main():
    p = argparse.ArgumentParser(prog="tailscalekeen")
    sub = p.add_subparsers(dest="command", required=True)
    x = sub.add_parser("uninstall")
    x.add_argument("--purge", action="store_true")
    x.add_argument("--dry-run", action="store_true")
    x.add_argument("--root", default="/")
    e = sub.add_parser("egress")
    e.add_argument("target")
    e.add_argument("--dry-run", action="store_true")
    sub.add_parser("reset-password")
    sub.add_parser("check-update")
    sub.add_parser("update")
    for name in ["start", "stop", "restart", "status", "doctor", "egress-sync", "integration-sync"]:
        sub.add_parser(name)
    a = p.parse_args()
    if a.command in ["reset-password", "update", "egress", "egress-sync", "integration-sync", "start", "stop", "restart"] and getattr(os, "geteuid", lambda: -1)() != 0:
        raise Error("Выполните команду от root через SSH", 403)
    if a.command in ["check-update", "update"]:
        from .panel_update import PanelUpdater
        from .core import operation_lock
        state = pathlib.Path("/opt/etc/tailscale-panel")
        if a.command == "update" and os.geteuid() != 0:
            raise Error("Выполните команду от root через SSH", 403)
        updater = PanelUpdater(state)
        with operation_lock(state):
            result = updater.check(True) if a.command == "check-update" else updater.prepare(lambda text: print(text, flush=True))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    if a.command == "reset-password":
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise Error("Выполните команду от root через SSH.", 403)
        from .accounts import Accounts

        state = pathlib.Path("/opt/etc/tailscale-panel")
        Accounts(state).reset()
        config = json.loads((state / "config.json").read_text())
        print(
            "Логин и пароль удалены. Панель возвращена к первому входу. Создайте новую учётную запись на порту "
            + str(config.get("port", 8092))
            + "."
        )
        return
    if a.command == "uninstall":
        from .uninstall import Purger

        root = pathlib.Path(a.root).resolve()
        state = root / "opt/etc/tailscale-panel"
        purger = Purger(state, root=str(root))
        if not a.purge and not a.dry_run:
            p.error("Для полного удаления укажите --purge. Просмотр: --dry-run")
        if a.dry_run:
            print(json.dumps(purger.plan(), ensure_ascii=False, indent=2))
            return
        if root == pathlib.Path("/"):
            subprocess.run(
                ["/opt/etc/init.d/S98tailscale-panel", "stop"], timeout=250, check=True
            )
        print(json.dumps(purger.purge(), ensure_ascii=False, indent=2))
        return
    if a.command in ["egress-sync", "egress", "integration-sync"]:
        from .service import Service
        from .core import operation_lock

        s = Service("/opt/etc/tailscale-panel")
        if s.panel_updater.active():
            raise Error("Сначала дождитесь обновления панели", 409)
        with operation_lock(s.state):
            if a.command == "egress":
                result = (
                    s.egress.plan({"target": a.target})
                    if a.dry_run
                    else s.egress.apply({"target": a.target}, lambda _: None)
                )
                print(json.dumps(result, ensure_ascii=False))
            elif a.command == "egress-sync":
                s.egress.sync()
            else:
                s.integration.sync(s.ts.snapshot(True))
        return
    if a.command == "doctor":
        from .service import Service

        s = Service("/opt/etc/tailscale-panel")
        x = s.dashboard()
        x["native"] = s.native.status()
        print(json.dumps(x, ensure_ascii=False, indent=2))
        return
    raise SystemExit(subprocess.call(["/opt/etc/init.d/S98tailscale-panel", a.command]))


if __name__ == "__main__":
    try:
        main()
    except Error as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1)
