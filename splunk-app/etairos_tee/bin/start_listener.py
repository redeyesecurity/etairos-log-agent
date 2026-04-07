#!/usr/bin/env python3
"""
Splunk scripted input wrapper for the Etairos Tee listener.
Runs as a persistent process (interval = -1).
Logs to $SPLUNK_HOME/var/log/splunk/etairos_tee.log
"""

import os
import sys
import logging
import signal
import time
from pathlib import Path

# Add app's lib directory to path for vendored dependencies
APP_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP_ROOT / "lib"))
sys.path.insert(0, str(APP_ROOT / "bin"))

# Determine SPLUNK_HOME (works on Linux, macOS, Windows)
SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunkforwarder")
LOG_FILE = Path(SPLUNK_HOME) / "var" / "log" / "splunk" / "etairos_tee.log"
CONFIG_FILE = APP_ROOT / "local" / "config.yaml"
if not CONFIG_FILE.exists():
    CONFIG_FILE = APP_ROOT / "default" / "config.yaml"

# Setup logging to Splunk's log directory
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [etairos_tee] %(message)s",
    handlers=[
        logging.FileHandler(str(LOG_FILE)),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger("etairos_tee")


def main():
    logger.info("=" * 60)
    logger.info("Etairos Tee starting")
    logger.info(f"SPLUNK_HOME: {SPLUNK_HOME}")
    logger.info(f"Config: {CONFIG_FILE}")
    logger.info(f"Log: {LOG_FILE}")
    logger.info(f"Platform: {sys.platform}")
    logger.info(f"Python: {sys.version}")
    logger.info("=" * 60)
    
    # Import the actual listener (after path setup)
    try:
        from listener import TeeListener
        import yaml
    except ImportError as e:
        logger.error(f"Import error: {e}")
        logger.error("Make sure all dependencies are in the lib/ folder")
        sys.exit(1)
    
    # Load config
    try:
        with open(CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f)
        logger.info(f"Loaded config from {CONFIG_FILE}")
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        sys.exit(1)
    
    # Validate required settings
    if config.get("forward", {}).get("enabled") and not config.get("forward", {}).get("host"):
        logger.error("forward.host is required when forward.enabled=true")
        logger.error("Edit local/config.yaml and set your indexer hostname")
        sys.exit(1)
    
    # Setup graceful shutdown
    shutdown_requested = False
    
    def handle_signal(signum, frame):
        nonlocal shutdown_requested
        logger.info(f"Received signal {signum}, shutting down...")
        shutdown_requested = True
    
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    if sys.platform != "win32":
        signal.signal(signal.SIGHUP, handle_signal)
    
    # Start the listener
    try:
        listener = TeeListener(config, logger)
        listener.start()
        
        # Keep running until shutdown signal
        while not shutdown_requested:
            time.sleep(1)
        
        listener.stop()
        logger.info("Etairos Tee stopped cleanly")
        
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
