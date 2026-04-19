"""
Rabin-Karp String Matching Algorithm for Web Application Firewall (WAF).

The Rabin-Karp algorithm is a pattern-matching technique that uses rolling hashes
to efficiently search for one or more patterns in a text. Key advantages:

- Average-case time complexity: O(n + m) vs naive O(nm)
- Efficient for multiple pattern searches (reuse hashing infrastructure)
- Suitable for detecting attack signatures in WAF context
- Trade-off: Higher probability of spurious hits (hash collisions) requires verification

In this WAF implementation:
- Detects malicious payloads (SQL injection, XSS patterns) by matching signatures
- Returns matched pattern immediately for efficient blocking
- Tracks spurious hits for performance monitoring

Reference: Disawal & Suman (2023) WV-DPM methodology for WAF pattern detection.
"""

BASE = 256          # Number of characters in the input alphabet
MOD = 101           # Prime number for hashing to avoid overflow


def rabin_karp_search(text, pattern):
    """
    Classic Rabin-Karp single pattern search.
    
    Args:
        text (str): The text to search in
        pattern (str): The pattern to search for
        
    Returns:
        int: Index of first match, or -1 if not found
    """
    text = text.lower()
    pattern = pattern.lower()
    
    n = len(text)
    m = len(pattern)
    
    if m > n:
        return -1
    if m == 0:
        return 0
    
    # Compute (BASE^(m-1)) % MOD for rolling hash update
    base_power = pow(BASE, m - 1, MOD)
    
    # Compute hash of pattern
    pattern_hash = 0
    for char in pattern:
        pattern_hash = (pattern_hash * BASE + ord(char)) % MOD
    
    # Compute hash of first window of text
    window_hash = 0
    for i in range(m):
        window_hash = (window_hash * BASE + ord(text[i])) % MOD
    
    # Slide window across text
    for i in range(n - m + 1):
        # If hash matches, verify character by character to avoid spurious hits
        if window_hash == pattern_hash:
            if text[i:i + m] == pattern:
                return i  # Match found
        
        # Compute rolling hash for next window (if not the last window)
        if i < n - m:
            # Remove leftmost character of current window: h = (h - text[i] * BASE^(m-1)) % MOD
            window_hash = (window_hash - ord(text[i]) * base_power) % MOD
            # Add new rightmost character
            window_hash = (window_hash * BASE + ord(text[i + m])) % MOD
            # Ensure hash is positive
            window_hash = (window_hash + MOD) % MOD
    
    return -1  # No match found


def rabin_karp_multi_search(text, patterns):
    """
    Search text against a list of patterns using Rabin-Karp.
    
    Args:
        text (str): The text to search in
        patterns (list[str]): List of patterns to search for
        
    Returns:
        str | None: First matching pattern, or None if no match
    """
    for pattern in patterns:
        if rabin_karp_search(text, pattern) != -1:
            return pattern
    return None


def rabin_karp_stats(text, patterns):
    """
    Search with statistics for profiling and debugging.
    
    Args:
        text (str): The text to search in
        patterns (list[str]): List of patterns to search for
        
    Returns:
        dict: Statistics including patterns checked, matched pattern, spurious hits, comparisons
    """
    text_lower = text.lower()
    total_patterns = len(patterns)
    matched = None
    total_spurious = 0
    total_comparisons = 0
    
    for pattern in patterns:
        pattern_lower = pattern.lower()
        n = len(text_lower)
        m = len(pattern_lower)
        
        if m > n or m == 0:
            continue
        
        base_power = pow(BASE, m - 1, MOD)
        pattern_hash = 0
        for char in pattern_lower:
            pattern_hash = (pattern_hash * BASE + ord(char)) % MOD
        
        window_hash = 0
        for i in range(m):
            window_hash = (window_hash * BASE + ord(text_lower[i])) % MOD
        
        # Slide and count comparisons
        for i in range(n - m + 1):
            if window_hash == pattern_hash:
                # Count characters compared during verification
                total_comparisons += m
                if text_lower[i:i + m] == pattern_lower:
                    matched = pattern
                    return {
                        "total_patterns_checked": total_patterns,
                        "matched_pattern": matched,
                        "spurious_hits": total_spurious,
                        "comparisons_made": total_comparisons,
                    }
                else:
                    # Spurious hit: hash matched but pattern didn't
                    total_spurious += 1
            
            if i < n - m:
                window_hash = (window_hash - ord(text_lower[i]) * base_power) % MOD
                window_hash = (window_hash * BASE + ord(text_lower[i + m])) % MOD
                window_hash = (window_hash + MOD) % MOD
    
    return {
        "total_patterns_checked": total_patterns,
        "matched_pattern": matched,
        "spurious_hits": total_spurious,
        "comparisons_made": total_comparisons,
    }


if __name__ == "__main__":
    # Self-tests
    tests_passed = 0
    tests_total = 3
    
    # Test 1: Single pattern match
    result = rabin_karp_search("hello world", "world")
    if result == 6:
        print("PASS: Test 1 (single pattern match)")
        tests_passed += 1
    else:
        print(f"FAIL: Test 1 (expected 6, got {result})")
    
    # Test 2: SQL injection pattern detection
    result = rabin_karp_multi_search(
        "username' OR '1'='1",
        ["OR", "UNION", "DROP"]
    )
    if result == "OR":
        print("PASS: Test 2 (SQL injection detection)")
        tests_passed += 1
    else:
        print(f"FAIL: Test 2 (expected 'OR', got {result})")
    
    # Test 3: No pattern match
    result = rabin_karp_search("safe input", "malicious")
    if result == -1:
        print("PASS: Test 3 (no pattern match)")
        tests_passed += 1
    else:
        print(f"FAIL: Test 3 (expected -1, got {result})")
    
    print(f"\nResults: {tests_passed}/{tests_total} tests passed")
