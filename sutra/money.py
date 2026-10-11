"""Indian rupee formatting: lakh and crore, the units an Indian board reads."""

LAKH = 100_000
CRORE = 10_000_000


def indian_grouping(n: int) -> str:
    s = str(abs(n))
    if len(s) > 3:
        head, tail = s[:-3], s[-3:]
        parts = []
        while len(head) > 2:
            parts.insert(0, head[-2:])
            head = head[:-2]
        if head:
            parts.insert(0, head)
        s = ",".join(parts + [tail])
    return ("-" if n < 0 else "") + s


def inr(amount: float) -> str:
    """₹4.2 crore, ₹18.5 lakh, or ₹45,000."""
    if amount >= CRORE:
        return f"₹{amount / CRORE:,.1f} crore"
    if amount >= LAKH:
        return f"₹{amount / LAKH:,.1f} lakh"
    return f"₹{indian_grouping(round(amount))}"
