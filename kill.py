"""HTTPS POST notification for unexpected SSH logins."""

import ipaddress
import json
import os
import socket
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

POST_URL = os.environ.get("BEMAN_ALERT_URL", "")  # Optional HTTPS endpoint.


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main(username, source_ip, *, user_allowed, ip_allowed):
    """Send an alert only for a login that fails either whitelist check."""
    if user_allowed and ip_allowed:
        return False
    if not POST_URL:
        return False
    target = urlsplit(POST_URL)
    if target.scheme != "https" or not target.hostname or target.username or target.password or target.fragment:
        raise ValueError("POST_URL must be a valid HTTPS endpoint")
    payload = {
        "event": "unexpected_ssh_login",
        "hostname": socket.gethostname(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": str(username),
        "source_ip": str(ipaddress.ip_address(source_ip)),
        "user_allowed": bool(user_allowed),
        "ip_allowed": bool(ip_allowed),
    }
    request = Request(
        POST_URL,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with build_opener(_NoRedirect()).open(request, timeout=5) as response:
            return 200 <= response.status < 300
    except (URLError, TimeoutError, OSError):
        return False
