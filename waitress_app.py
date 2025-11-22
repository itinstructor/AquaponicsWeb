"""
Filename: waitress_app.py
Description: This script sets up and runs a Waitress WSGI server
to serve a Flask web application.
"""

import os, sys, logging, traceback
from logging_config import setup_logging
setup_logging("waitress_app.log")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

try:
    import main_app
    app = getattr(main_app, "app", None)
    if app is None:
        raise RuntimeError("Flask app not found (expected main_app.app)")
except Exception as e:
    logging.critical("Failed importing main_app: %s\n%s", e, traceback.format_exc())
    raise

logging.getLogger(__name__).info("=== Waitress WSGI app initializing ===")

def main():
    from waitress import serve
    port = int(os.environ.get("HTTP_PLATFORM_PORT", 8080))
    logging.info(f"Starting Waitress on 127.0.0.1:{port}")
    try:
        serve(app, host="127.0.0.1", port=port, threads=32)
    except Exception as e:
        logging.critical("Waitress serve failed: %s\n%s", e, traceback.format_exc())
        raise

if __name__ == "__main__":
    main()


