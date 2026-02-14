from __future__ import annotations

import argparse

from .app import (
    create_configurator_app,
    create_experience_studio_app,
    create_landing_app,
    create_rules_engine_app,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run sales configurator services")
    parser.add_argument("service", choices=["landing", "rules", "configurator", "experience"])
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", default="./data.db")
    args = parser.parse_args()

    if args.service == "landing":
        app = create_landing_app(args.db)
    elif args.service == "rules":
        app = create_rules_engine_app(args.db)
    elif args.service == "configurator":
        app = create_configurator_app(args.db)
    else:
        app = create_experience_studio_app(args.db)

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
