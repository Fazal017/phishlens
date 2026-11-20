"""PhishLens — phishing URL & email header analyzer (stdlib only)."""

__version__ = "1.0.0"
__all__ = ["analyze_url", "analyze_email"]

from .url_analyzer import analyze_url
from .email_analyzer import analyze_email
