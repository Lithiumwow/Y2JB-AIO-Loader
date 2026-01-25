import logging
import threading
from src.repo_manager import update_payloads

def setup_logging(config):
    level = logging.DEBUG if config.get("debug_mode") == "true" else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    logger = logging.getLogger("Y2JB")
    logger.info(f"Logging initialized at {'DEBUG' if level == logging.DEBUG else 'INFO'} level")

def run_startup_tasks(config):
    if config.get("auto_update_repos", "true") == "true":
        print("[STARTUP] Auto-updating repositories...")
        threading.Thread(target=lambda: update_payloads(['all']), daemon=True).start()
