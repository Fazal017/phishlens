"""Three-dimensional brand squatting (PhishLens v2).

v1 scored a domain on one axis only: plain Levenshtein edit distance.
Attackers who survive that check use three other tricks, so v2 scores
every candidate label on three *independent* dimensions and a domain
only needs to be close on one of them to be flagged:

(a) Edit distance -- Damerau-Levenshtein (insert / delete / substitute
    / *transposition*). ``paypall`` (insertion) and ``paypla`` (a
    transposition of the last two letters) are 1 edit away; plain
    Levenshtein also counts the transposition as 2, so it misses it.
(b) Phonetic similarity -- a Soundex-like code plus a vowel-swap
    normalisation. ``paypel`` / ``paypol`` sound like ``paypal`` even
    though the spelling differs, and ``paypaI`` (capital i for l)
    normalises to the same phonetic shape.
(c) Keyboard-adjacency distance -- QWERTY-neighbour weighted edit
    distance. A substitution costs 0.5 when the two keys are adjacent
    (``paypak``: k sits next to l) and 1.0 otherwise, so a typo that
    could plausibly be a fat-fingered ``paypal`` scores closer than a
    random one-letter change.

A finding is only raised when the candidate is *not* the brand's own
domain. Legitimate ``paypal.com`` scores 0 on all three dimensions.
Stdlib only, no network.
"""

import re

from .brands import BRAND_ALIASES, is_legitimate_brand_domain, registered_domain

# Digits visually swapped for letters in typosquats (same map as v1).
DIGIT_FOR_LETTER = {"0": "o", "1": "l", "5": "s", "3": "e"}

# QWERTY rows (lowercase). Neighbours are left/right on the same row,
# plus the key directly above/below in the staggered layout (approximated
# by index +/- 1 in the row above/below).
_QWERTY_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]


def _neighbours(ch):
    out = set()
    for r, row in enumerate(_QWERTY_ROWS):
        if ch not in row:
            continue
        i = row.index(ch)
        if i > 0:
            out.add(row[i - 1])
        if i < len(row) - 1:
            out.add(row[i + 1])
        for dr in (-1, 1):
            nr = r + dr
            if 0 <= nr < len(_QWERTY_ROWS):
                other = _QWERTY_ROWS[nr]
                for j in (i - 1, i, i + 1):
                    if 0 <= j < len(other):
                        out.add(other[j])
    return out


_NEIGHBOURS = {ch: _neighbours(ch) for row in _QWERTY_ROWS for ch in row}


def is_keyboard_neighbour(a, b):
    return b in _NEIGHBOURS.get(a, set())


def damerau_levenshtein(a, b):
    """Damerau-Levenshtein distance (transposition costs 1)."""
    a, b = a.lower(), b.lower()
    la, lb = len(a), len(b)
    # d[i][j] = distance between a[:i] and b[:j]
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1,
                          d[i - 1][j - 1] + cost)
            if (i > 1 and j > 1 and a[i - 1] == b[j - 2]
                    and a[i - 2] == b[j - 1]):
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def keyboard_distance(a, b):
    """Edit distance where an adjacent-key substitution costs 0.5.

    Insertions/deletions cost 1.0, non-adjacent substitutions 1.0.
    Returns a float; a value <= 1.0 means "one plausible typo away".
    """
    a, b = a.lower(), b.lower()
    la, lb = len(a), len(b)
    d = [[0.0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = float(i)
    for j in range(lb + 1):
        d[0][j] = float(j)
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            if a[i - 1] == b[j - 1]:
                sub = 0.0
            elif is_keyboard_neighbour(a[i - 1], b[j - 1]):
                sub = 0.5
            else:
                sub = 1.0
            d[i][j] = min(d[i - 1][j] + 1.0, d[i][j - 1] + 1.0,
                          d[i - 1][j - 1] + sub)
    return d[la][lb]


def keyboard_adjacent_substitutions(a, b):
    """Count positions where the letters differ but are QWERTY neighbours."""
    if len(a) != len(b):
        return 0
    return sum(1 for x, y in zip(a.lower(), b.lower())
               if x != y and is_keyboard_neighbour(x, y))


# --- Phonetics ---------------------------------------------------------

_SOUNDEX_MAP = {}
for _ch in "bfpv":
    _SOUNDEX_MAP[_ch] = "1"
for _ch in "cgjkqsxz":
    _SOUNDEX_MAP[_ch] = "2"
for _ch in "dt":
    _SOUNDEX_MAP[_ch] = "3"
_SOUNDEX_MAP["l"] = "4"
for _ch in "mn":
    _SOUNDEX_MAP[_ch] = "5"
_SOUNDEX_MAP["r"] = "6"


def soundex(word):
    """Classic Soundex code (4 chars). Vowels / h / w / y are dropped."""
    word = re.sub(r"[^a-z]", "", word.lower())
    if not word:
        return "0000"
    first = word[0].upper()
    coded = []
    prev = _SOUNDEX_MAP.get(first, "")
    for ch in word[1:]:
        code = _SOUNDEX_MAP.get(ch, "")
        if code and code != prev:
            coded.append(code)
        prev = code
    return (first + "".join(coded) + "000")[:4]


def vowel_normalised(word):
    """Replace every vowel with 'a' and map lookalike digits to letters.

    ``paypel``, ``paypol``, ``paypa1`` and ``paypaI`` all normalise to
    ``paypal``-shaped strings, so a vowel-swap typosquat is caught even
    when its edit distance is the same as a random change.
    """
    out = []
    for ch in word.lower():
        ch = DIGIT_FOR_LETTER.get(ch, ch)
        if ch in "aeiou":
            out.append("a")
        elif ch == "i":  # capital-I lookalike for lowercase L, after lower()
            out.append("l")
        elif ch.isalnum():
            out.append(ch)
    # 'I' lowercases to 'i', which is a vowel above; handle the
    # lookalike explicitly: a lone 'i' standing in for 'l' is caught
    # by the digit/letter map in the caller, see _normalise_label.
    return "".join(out)


def _normalise_label(label):
    """Map lookalike digits (1->l, 0->o) and strip non-alphanumerics."""
    return "".join(DIGIT_FOR_LETTER.get(ch, ch)
                   for ch in label.lower() if ch.isalnum())


def phonetic_match(a, b):
    """True if the two words share a Soundex code or vowel shape."""
    if soundex(a) == soundex(b):
        return True
    return vowel_normalised(a) == vowel_normalised(b)


# --- Combined analysis -------------------------------------------------

def analyze_squatting_label(label, brand):
    """Score one domain label against one brand on all three dimensions.

    Returns a dict; ``dimensions`` lists which axes fired.
    """
    norm = _normalise_label(label)
    # 'paypaI' (capital i for l) is 1 Damerau edit from 'paypal':
    # i -> l. Do NOT map i->l before scoring, or the distance
    # collapses to 0 and the squat disappears.
    edit = damerau_levenshtein(norm, brand)
    kb = keyboard_distance(norm, brand)
    kb_adj = keyboard_adjacent_substitutions(norm, brand)
    phon = phonetic_match(norm, brand)
    vowel = vowel_normalised(norm) == vowel_normalised(brand)
    dimensions = []
    if edit == 1:
        dimensions.append("edit-1")
    elif edit == 2:
        dimensions.append("edit-2")
    if phon:
        dimensions.append("phonetic")
    if vowel and norm != brand:
        dimensions.append("vowel-swap")
    if kb <= 1.0 and norm != brand:
        dimensions.append("keyboard")
    return {
        "label": label, "normalised": norm, "brand": brand,
        "damerau_distance": edit, "keyboard_distance": kb,
        "keyboard_adjacent_substitutions": kb_adj,
        "soundex_label": soundex(norm), "soundex_brand": soundex(brand),
        "phonetic_match": phon, "vowel_swap_match": vowel,
        "dimensions": dimensions,
    }


def closest_brand_3d(label):
    """Best (brand, analysis) over all brands, ranked by edit distance."""
    best = None
    for alias, brand in BRAND_ALIASES.items():
        analysis = analyze_squatting_label(label, brand)
        key = (analysis["damerau_distance"], analysis["keyboard_distance"])
        if best is None or key < best[0]:
            best = (key, brand, analysis)
    return best[1], best[2]


def squat_findings(host):
    """Findings (rule tuples) for 3-D squatting on a host name.

    Each tuple is (rule_id, severity, weight, title, explanation,
    remediation) in the same shape the v1 analysers use, so the v2
    CLI can merge them into an AnalysisResult.
    """
    host = (host or "").lower().strip(".")
    if not host:
        return []
    findings = []
    labels = host.split(".")
    reg = registered_domain(host)
    reg_label = labels[-2] if len(labels) >= 2 else host

    # (1) Brand embedded in a longer label: paypal-secure, paypal-login.
    # Caught differently from a typosquat: the brand is intact, the
    # domain just is not the brand's.
    for label in labels:
        norm = _normalise_label(label)
        for alias, brand in BRAND_ALIASES.items():
            if alias in norm and norm != alias and not is_legitimate_brand_domain(host, brand):
                findings.append((
                    "SQ-EMBEDDED-BRAND", "high", 35,
                    f"Brand '{brand}' embedded in label '{label}'",
                    f"The label '{label}' contains the intact brand name "
                    f"'{brand}', but the registrable domain is {reg} — "
                    "not the brand's. The brand text is a lure, not an owner.",
                    "A brand name inside a longer domain does not make "
                    "it the brand's site."))
                break

    # (2) 3-D squatting on the registrable label.
    brand, analysis = closest_brand_3d(reg_label)
    if brand and not is_legitimate_brand_domain(host, brand):
        dims = analysis["dimensions"]
        if "edit-1" in dims:
            findings.append((
                "SQ-EDIT-1", "critical", 50,
                f"1-edit typosquat: '{reg_label}' is 1 Damerau edit from '{brand}'",
                f"Damerau-Levenshtein distance is 1 (insert/delete/substitute/"
                f"transposition). Dimensions firing: {', '.join(dims) or 'edit-1'}.",
                "Type the brand's domain yourself; do not trust a near-miss spelling."))
        elif "edit-2" in dims:
            findings.append((
                "SQ-EDIT-2", "critical", 40,
                f"2-edit typosquat: '{reg_label}' is 2 Damerau edits from '{brand}'",
                f"Damerau-Levenshtein distance is 2. Dimensions firing: "
                f"{', '.join(dims)}.",
                "Type the brand's domain yourself; do not trust a near-miss spelling."))
        elif "phonetic" in dims or "vowel-swap" in dims:
            findings.append((
                "SQ-PHONETIC", "high", 35,
                f"Phonetic squat: '{reg_label}' sounds like '{brand}' "
                f"(Soundex {analysis['soundex_label']} vs {analysis['soundex_brand']})",
                "The spelling differs but the name sounds identical — a "
                "vowel-swap / sound-alike squat that survives a plain "
                "edit-distance check.",
                "Say the domain out loud and compare it with the real brand."))
        elif "keyboard" in dims:
            findings.append((
                "SQ-KEYBOARD", "high", 35,
                f"Keyboard squat: '{reg_label}' is a QWERTY-neighbour typo of '{brand}' "
                f"(keyboard distance {analysis['keyboard_distance']})",
                "The differing letter sits next to the correct one on a "
                "QWERTY keyboard — a fat-finger typo domain built to "
                "catch mistypes.",
                "Type the brand's domain yourself; do not trust a near-miss spelling."))
        # Extra detail finding when several dimensions agree at once:
        # that is stronger evidence than any single axis.
        if len(dims) >= 2 and "edit-1" not in dims:
            findings.append((
                "SQ-MULTI-DIMENSION", "high", 20,
                f"Multiple squatting dimensions agree on '{brand}': {', '.join(dims)}",
                "Edit, phonetic and keyboard checks independently point "
                "at the same brand — a deliberate squat, not a coincidence.",
                "Treat the domain as a brand impersonation."))
    return findings
