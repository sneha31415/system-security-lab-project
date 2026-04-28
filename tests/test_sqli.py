import time
from pathlib import Path

import requests


BASE_URL = "http://127.0.0.1:5000"
PAYLOAD_FILE = Path(__file__).parent / "payloads" / "sqli_payloads.txt"

# Fallback payloads used if payload file is missing/empty.
FALLBACK_PAYLOADS = [
	"' OR '1'='1",
	"' OR 1=1 --",
	"admin'--",
	"' UNION SELECT 1,2 --",
	"' UNION SELECT username,password FROM users --",
	"'; DROP TABLE users; --",
	"' AND SLEEP(5) --",
	"' AND 1=(SELECT 1) --",
	"'/**/OR/**/1=1/**/--",
	"0x27204f5220313d31202d2d",
]


def load_payloads():
	if PAYLOAD_FILE.exists():
		payloads = []
		for line in PAYLOAD_FILE.read_text(encoding="utf-8").splitlines():
			value = line.strip()
			if value and not value.startswith("#"):
				payloads.append(value)
		if payloads:
			return payloads
	return FALLBACK_PAYLOADS


def test_sqli_detection():
	payloads = load_payloads()
	blocked = 0
	missed = 0

	print("\n=== SQL Injection Detection Test ===")
	print(f"Testing {len(payloads)} payload(s) against {BASE_URL}/login")

	for payload in payloads:
		try:
			response = requests.post(
				f"{BASE_URL}/login",
				data={"username": payload, "password": "x"},
				timeout=5,
				allow_redirects=False,
			)

			if response.status_code == 403:
				blocked += 1
				print(f"[BLOCKED] {payload}")
			else:
				missed += 1
				print(f"[MISSED]  {payload} (status={response.status_code})")
		except requests.RequestException as exc:
			missed += 1
			print(f"[MISSED]  {payload} (request error: {exc})")

		time.sleep(0.05)

	total = blocked + missed
	rate = (blocked / total * 100) if total else 0.0
	print(f"Detection Rate: {blocked}/{total} = {rate:.2f}%")

	return {
		"total": total,
		"blocked": blocked,
		"missed": missed,
		"detection_rate": rate,
	}


def test_false_positives():
	normal_usernames = ["alice", "john_doe", "user123", "O'Brien"]
	false_positives = 0

	print("\n=== False Positive Test ===")
	print(f"Testing {len(normal_usernames)} normal username(s)")

	for username in normal_usernames:
		try:
			response = requests.post(
				f"{BASE_URL}/login",
				data={"username": username, "password": "x"},
				timeout=5,
				allow_redirects=False,
			)

			if response.status_code == 403:
				false_positives += 1
				print(f"[FALSE POSITIVE] {username}")
			else:
				print(f"[OK]             {username} (status={response.status_code})")
		except requests.RequestException as exc:
			print(f"[SKIPPED]        {username} (request error: {exc})")

		time.sleep(0.05)

	total = len(normal_usernames)
	fp_rate = (false_positives / total * 100) if total else 0.0
	print(f"False Positive Rate: {false_positives}/{total} = {fp_rate:.2f}%")

	return {
		"total": total,
		"false_positives": false_positives,
		"false_positive_rate": fp_rate,
	}


if __name__ == "__main__":
	print("Running SQLi automated tests...")
	print("Make sure the Flask app is running at http://127.0.0.1:5000")

	sqli_result = test_sqli_detection()
	fp_result = test_false_positives()

	print("\n=== Summary ===")
	print("+----------------------+-------+-------+----------+")
	print("| Metric               | Total | Count | Rate     |")
	print("+----------------------+-------+-------+----------+")
	print(
		"| SQLi Detection       | "
		f"{sqli_result['total']:5d} | {sqli_result['blocked']:5d} | {sqli_result['detection_rate']:7.2f}% |"
	)
	print(
		"| False Positives      | "
		f"{fp_result['total']:5d} | {fp_result['false_positives']:5d} | {fp_result['false_positive_rate']:7.2f}% |"
	)
	print("+----------------------+-------+-------+----------+")
