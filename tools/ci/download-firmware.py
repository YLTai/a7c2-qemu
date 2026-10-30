#!/usr/bin/env python3
"""Runner-only download: never print the URL, redirects or exception details."""
import hashlib
import os
from pathlib import Path
import sys
import urllib.parse
import urllib.request

class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('Unsafe redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def main():
    url = os.environ.pop('SONY_FIRMWARE_URL', '')
    if not url:
        print('FIRMWARE_NOT_RUN: required repository secret is missing')
        return 2
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Unsupported source')
    root = Path(os.environ['RUNNER_TEMP']).resolve()
    target = root / 'sony-private-input' / 'BODYDATA.DAT'
    target.parent.mkdir(mode=0o700, exist_ok=False)
    digest = hashlib.sha256()
    size = 0
    opener = urllib.request.build_opener(HTTPSRedirect())
    with opener.open(url, timeout=60) as response, target.open('xb') as stream:
        while data := response.read(1024 * 1024):
            size += len(data)
            if size > 4 * 1024**3:
                raise ValueError('Download exceeds limit')
            stream.write(data)
            digest.update(data)
    target.chmod(0o600)
    print('FIRMWARE_DOWNLOADED bytes=%d sha256=%s; identity verification pending' % (size, digest.hexdigest()))
    return 0

if __name__ == '__main__':
    try:
        result = main()
    except Exception:
        # Intentionally omit exception text/traceback: it can include the secret URL.
        print('FIRMWARE_DOWNLOAD_FAILED: details suppressed to protect source URL')
        result = 1
    sys.exit(result)
