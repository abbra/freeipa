# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""REST API package for IPAthinCA — Flask blueprint-based implementation."""

import logging

from flask import Flask, request

from ipathinca.rest_api_helpers import error_response
import ipathinca.rest_api._globals as _g

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.errorhandler(404)
def not_found(error):
    return error_response(
        "NotFound", f"Endpoint not found: {request.path}", 404
    )


@app.errorhandler(500)
def internal_error(error):
    logger.error("Internal server error: %s", error)
    return error_response("InternalServerError", "Internal server error", 500)


# Register blueprints (import after app is created to avoid circular imports)
from ipathinca.rest_api import (  # noqa: E402
    ca_core, certs, profiles, crl_ocsp, authorities, ranges, kra, acme, hsm,
)

for _bp_mod in (
    ca_core, certs, profiles, crl_ocsp, authorities, ranges, kra, acme, hsm
):
    app.register_blueprint(_bp_mod.bp)


def create_app(config=None):
    """Application factory."""
    if config:
        if "config" in config:
            _g.ipa_ca_config = config["config"]
            log_level_str = _g.ipa_ca_config.get(
                "logging", "level", fallback="INFO"
            )
            log_level = getattr(logging, log_level_str.upper(), logging.INFO)
            logging.getLogger("ipathinca").setLevel(log_level)
        app.config.update(config)

    with app.app_context():
        _g.init_ca()

    return app


def main():
    """Entry point for running the server directly (development only)."""
    import argparse

    parser = argparse.ArgumentParser(description="IPAthinCA REST API Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--ssl-cert", help="SSL certificate file")
    parser.add_argument("--ssl-key", help="SSL key file")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    ssl_context = None
    if args.ssl_cert and args.ssl_key:
        ssl_context = (args.ssl_cert, args.ssl_key)

    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        ssl_context=ssl_context,
    )


# Re-export for wsgi.py compat: from ipathinca.rest_api import ca_backend
# NOTE: This is a snapshot at import time. Use _g.ca_backend for the live value.
def __getattr__(name):
    if name == "ca_backend":
        return _g.ca_backend
    if name == "kra_backend":
        return _g.kra_backend
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
