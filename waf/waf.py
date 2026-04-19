from werkzeug.wrappers import Request, Response

from .sanitiser import sanitise, is_encoded
from .blacklist import blacklist_check
from .rabin_karp import rabin_karp_search, rabin_karp_stats
from .logger import log_attack, log_clean
from . import patterns
import re


class WAFMiddleware:
	def __init__(self, app):
		self.app = app
		self.total_requests = 0
		self.total_blocked = 0
		self.blocked_by_layer = {1: 0, 2: 0, 3: 0}

	def __call__(self, environ, start_response):
		request = Request(environ)
		self.total_requests += 1

		threat = self._inspect_request(request)
		if threat:
			self.total_blocked += 1
			self.blocked_by_layer[threat["layer"]] += 1
			log_attack(request, threat)

			html_body = f"""
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>403 - Blocked by WAF</title>
  <style>
	body {{ font-family: Arial, sans-serif; background: #f9f9f9; color: #222; margin: 0; }}
	.wrap {{ max-width: 760px; margin: 2rem auto; padding: 2rem; background: #fff; border: 1px solid #ddd; }}
	h1 {{ color: #b00020; margin-top: 0; }}
	.meta {{ background: #fafafa; border: 1px solid #eee; padding: 1rem; margin: 1rem 0; }}
	.meta p {{ margin: 0.45rem 0; }}
	a {{ color: #222; }}
  </style>
</head>
<body>
  <main class=\"wrap\">
	<h1>403 — Blocked by WAF</h1>
	<div class=\"meta\">
	  <p><strong>Detection Layer:</strong> Layer {threat['layer']}</p>
	  <p><strong>Algorithm:</strong> {threat.get('algorithm', 'Unknown')}</p>
	  <p><strong>Reason:</strong> {threat.get('reason', 'Suspicious request detected')}</p>
	</div>
	<p><a href=\"/\">Back to Home</a></p>
  </main>
</body>
</html>
			""".strip()

			response = Response(html_body, status=403, content_type="text/html; charset=utf-8")
			return response(environ, start_response)

		log_clean(request)
		return self.app(environ, start_response)

	def _inspect_request(self, request):
		values = []

		for field, value in request.args.items(multi=True):
			values.append((field, value))
		for field, value in request.form.items(multi=True):
			values.append((field, value))
		for field, value in request.cookies.items():
			values.append((field, value))

		for field, value in values:
			if value is None:
				continue
			text_value = str(value)
			if text_value.strip() == "":
				continue

			# LAYER 1: Rabin-Karp exact signature matching on raw value.
			result = blacklist_check(text_value)
			if result:
				return {
					"layer": 1,
					"field": field,
					"reason": f"Rabin-Karp matched: {result['matched']}",
					"algorithm": "Rabin-Karp",
					"attack_type": result.get("type"),
				}

			# LAYER 2: Decode encoded payloads and re-check with both mechanisms.
			safe_val, decoded = sanitise(text_value)
			_ = safe_val
			if is_encoded(text_value, decoded):
				result = blacklist_check(decoded)
				if result:
					return {
						"layer": 2,
						"field": field,
						"reason": f"Encoded payload - Rabin-Karp matched: {result['matched']}",
						"algorithm": "Rabin-Karp",
						"attack_type": result.get("type"),
					}

				regex_match = self._regex_check(decoded)
				if regex_match:
					return {
						"layer": 2,
						"field": field,
						"reason": f"Encoded payload - Regex structural match: {regex_match}",
						"algorithm": "Regex",
						"attack_type": "Structural",
					}

			# LAYER 3: Structural regex matching for wildcard/obfuscated payloads.
			regex_match = self._regex_check(text_value)
			if regex_match:
				return {
					"layer": 3,
					"field": field,
					"reason": f"Regex structural match: {regex_match}",
					"algorithm": "Regex",
					"attack_type": "Structural",
				}

		return None

	def _regex_check(self, value):
		value_lower = str(value).lower()
		all_patterns = list(getattr(patterns, "SQLI_PATTERNS", [])) + list(
			getattr(patterns, "XSS_PATTERNS", [])
		)

		for pattern in all_patterns:
			if re.search(pattern, value_lower, re.IGNORECASE):
				return pattern

		return None

	def get_stats(self):
		if self.total_requests == 0:
			detection_rate = 0.0
		else:
			detection_rate = (self.total_blocked / self.total_requests) * 100.0

		return {
			"total_requests": self.total_requests,
			"total_blocked": self.total_blocked,
			"blocked_by_layer": self.blocked_by_layer,
			"detection_rate": round(detection_rate, 2),
		}
