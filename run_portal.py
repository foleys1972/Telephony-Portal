from __future__ import annotations

import os

from portal_app import create_app
from portal_app.paths import resolve_port

app = create_app()


if __name__ == "__main__":
    port = resolve_port(default=5500)
    host = os.environ.get("TELEPHONY_HOST", "0.0.0.0")
    if host.strip() in {"*", "0", "0.0.0.0"}:
        host = "0.0.0.0"

    try:
        from waitress import serve

        serve(
            app,
            host=host,
            port=port,
            threads=max(1, int(os.environ.get("TELEPHONY_WAITRESS_THREADS", "8"))),
        )
    except ModuleNotFoundError:
        app.run(host=host, port=port, debug=False)
