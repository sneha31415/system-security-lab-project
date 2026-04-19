from datetime import datetime
from pathlib import Path

from config import LOG_FILE


def _write_log_line(message: str) -> None:
	log_path = Path(LOG_FILE)
	log_path.parent.mkdir(parents=True, exist_ok=True)
	with log_path.open("a", encoding="utf-8") as f:
		f.write(message + "\n")


def log_attack(request, threat: dict) -> None:
	timestamp = datetime.utcnow().isoformat()
	client_ip = request.remote_addr or "unknown"
	method = request.method
	path = request.path
	reason = threat.get("reason", "unknown")
	layer = threat.get("layer", "?")
	algorithm = threat.get("algorithm", "Unknown")
	attack_type = threat.get("attack_type", "Unknown")

	_write_log_line(
		f"[{timestamp}] ATTACK_BLOCKED ip={client_ip} method={method} path={path} "
		f"layer={layer} algorithm={algorithm} type={attack_type} reason={reason}"
	)


def log_clean(request) -> None:
	timestamp = datetime.utcnow().isoformat()
	client_ip = request.remote_addr or "unknown"
	method = request.method
	path = request.path

	_write_log_line(f"[{timestamp}] CLEAN_REQUEST ip={client_ip} method={method} path={path}")
