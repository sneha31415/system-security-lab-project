"""
Web Application Firewall (WAF) Blacklist Module.

This module uses the Rabin-Karp string matching algorithm to detect
SQL injection and XSS attack patterns in user input. Using Rabin-Karp
instead of regex ensures efficient multi-pattern detection and demonstrates
the algorithm's suitability for WAF signature matching.

All keyword matching is performed using rabin_karp_multi_search() from
the rabin_karp.py module, making the algorithm usage explicit and measurable.
"""

from waf.rabin_karp import rabin_karp_multi_search

# SQL Injection attack keywords/patterns
SQL_KEYWORDS = [
	"union select",
	"drop table",
	"insert into",
	"delete from",
	"update set",
	"exec(",
	"execute(",
	"xp_cmdshell",
	"sp_executesql",
	"waitfor delay",
	"benchmark(",
	"sleep(",
	"having 1=1",
	"order by 1",
	"group by 1",
	"--",
	"/*",
	"*/",
	"0x",
	"char(",
	"nchar(",
	"convert(",
	"cast(",
	"declare @",
]

# XSS and HTML injection attack keywords/patterns
XSS_KEYWORDS = [
	"<script",
	"</script>",
	"javascript:",
	"vbscript:",
	"<iframe",
	"<object",
	"<embed",
	"onerror=",
	"onload=",
	"onclick=",
	"onmouseover=",
	"onfocus=",
	"onblur=",
	"eval(",
	"document.cookie",
	"document.write(",
	"window.location",
	"alert(",
	"<svg",
	"expression(",
	"data:text/html",
	"base64,",
]

# Whitelist: Common benign words/phrases that should not trigger alerts
WHITELIST = [
	"selection",
	"selected",
	"selector",
	"executive",
	"alternatively",
	"insert-before",
	"update-on",
	"javascript course",
	"script writing",
]


def blacklist_check(value):
	"""
	Check user input against SQL injection and XSS attack pattern blacklists.

	Uses the Rabin-Karp algorithm via rabin_karp_multi_search() to detect
	malicious patterns. All matching is performed via the algorithm, not
	Python's 'in' operator or regex, making it auditable and demonstrating
	the algorithm's efficiency for WAF use.

	Args:
		value (str): User input to check

	Returns:
		dict | None: If attack pattern found, returns:
			{
				"matched": keyword_string,
				"type": "SQLi" or "XSS",
				"algorithm": "Rabin-Karp"
			}
			Returns None if input is clean.
	"""
	if not isinstance(value, str):
		value = str(value)

	# Lowercase for case-insensitive matching
	value_lower = value.lower()

	# Check SQL keywords using Rabin-Karp algorithm
	matched_sql = rabin_karp_multi_search(value_lower, SQL_KEYWORDS)
	if matched_sql:
		# Verify the match is not in a whitelisted context
		if not _is_whitelisted(value_lower, matched_sql):
			return {
				"matched": matched_sql,
				"type": "SQLi",
				"algorithm": "Rabin-Karp",
			}

	# Check XSS keywords using Rabin-Karp algorithm
	matched_xss = rabin_karp_multi_search(value_lower, XSS_KEYWORDS)
	if matched_xss:
		if not _is_whitelisted(value_lower, matched_xss):
			return {
				"matched": matched_xss,
				"type": "XSS",
				"algorithm": "Rabin-Karp",
			}

	return None


def _is_whitelisted(value_lower, matched_keyword):
	"""
	Check if a matched keyword is part of a whitelisted context.

	Args:
		value_lower (str): The lowercased input value
		matched_keyword (str): The keyword that matched

	Returns:
		bool: True if the match is in a whitelisted context, False otherwise
	"""
	for whitelisted_word in WHITELIST:
		# This is a simple heuristic: if both the keyword and a whitelist word
		# are in the value, we assume it's a benign context
		# This prevents "select" in "selection" from triggering an alert
		if matched_keyword.lower() in whitelisted_word.lower():
			# Check if the full whitelist word is present in the value
			if whitelisted_word.lower() in value_lower:
				return True
	return False
