#!/usr/bin/env python3
"""Mint a GitHub App installation token.

Usage:
    python3 mint-token.py <app_id> <private_key_pem_or_path> <installation_id>

Outputs the raw installation token to stdout (no trailing newline).
The token is valid for ~1 hour and scoped to the installation's repos.
"""
import sys
import time
import json
import urllib.request

try:
    import jwt
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'PyJWT[crypto]', '-q'])
    import jwt


def main():
    if len(sys.argv) != 4:
        print(f'Usage: {sys.argv[0]} <app_id> <private_key_pem_or_path> <installation_id>',
              file=sys.stderr)
        sys.exit(1)

    app_id, pem_path_or_content, installation_id = sys.argv[1], sys.argv[2], int(sys.argv[3])

    # Accept either raw PEM content or a file path
    if pem_path_or_content.strip().startswith('-----'):
        pem = pem_path_or_content
    else:
        with open(pem_path_or_content) as f:
            pem = f.read()

    now = int(time.time())
    app_jwt = jwt.encode(
        {'iat': now - 60, 'exp': now + 600, 'iss': str(app_id)},
        pem,
        algorithm='RS256',
    )

    req = urllib.request.Request(
        f'https://api.github.com/app/installations/{installation_id}/access_tokens',
        method='POST',
        headers={
            'Authorization': f'Bearer {app_jwt}',
            'Accept': 'application/vnd.github+json',
            'User-Agent': 'ez-appsec/1.0',
        },
    )
    with urllib.request.urlopen(req) as resp:
        token = json.load(resp)['token']

    print(token, end='')


if __name__ == '__main__':
    main()
