#!/usr/bin/env python3
"""Idempotent provisioner: push ez-appsec scan workflow + set secrets/variables in target repos.

Usage:
    python3 provision.py \
        --token <installation_token> \
        --repos owner/repo1,owner/repo2 \
        --app-id <numeric_app_id> \
        --private-key <pem_content_or_path>

The provisioner:
  1. Reads github/templates/scan.yml from this repo (or the working directory)
  2. For each target repo:
     a. PUT .github/workflows/ez-appsec-scan.yml (create-or-update, idempotent)
     b. SET secret EZ_APPSEC_APP_ID
     c. SET secret EZ_APPSEC_PRIVATE_KEY  (Libsodium-encrypted with repo public key)
     d. SET variable EZ_APPSEC_DASHBOARD_REPO = ez-appsec/ez-appsec-dashboard
"""
import argparse
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

DASHBOARD_REPO = 'ez-appsec/ez-appsec-dashboard'
WORKFLOW_DEST = '.github/workflows/ez-appsec-scan.yml'
TEMPLATE_PATHS = [
    os.path.join(os.path.dirname(__file__), '..', 'github', 'templates', 'scan.yml'),
    'github/templates/scan.yml',
]


# ---------------------------------------------------------------------------
# Dependency: PyNaCl for secret encryption
# ---------------------------------------------------------------------------
def _ensure_nacl():
    try:
        from nacl.public import PublicKey, SealedBox  # noqa: F401
        from nacl.encoding import Base64Encoder  # noqa: F401
    except ImportError:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'PyNaCl', '-q'])


_ensure_nacl()
from nacl.public import PublicKey, SealedBox  # noqa: E402
from nacl.encoding import Base64Encoder  # noqa: E402


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------
def _api(method: str, path: str, token: str, body=None):
    url = f'https://api.github.com{path}'
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json',
            'User-Agent': 'ez-appsec-provisioner/1.0',
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else {}


def _get_file_sha(repo: str, path: str, token: str):
    """Return (sha, exists) for the file, or (None, False) if absent."""
    status, data = _api('GET', f'/repos/{repo}/contents/{path}', token)
    if status == 200:
        return data.get('sha'), True
    return None, False


def _put_file(repo: str, path: str, content: str, token: str, message: str, sha=None):
    body = {
        'message': message,
        'content': base64.b64encode(content.encode()).decode(),
    }
    if sha:
        body['sha'] = sha
    status, data = _api('PUT', f'/repos/{repo}/contents/{path}', token, body)
    if status not in (200, 201):
        raise RuntimeError(f'PUT {path} in {repo} failed ({status}): {data}')
    return data


def _get_repo_public_key(repo: str, token: str):
    status, data = _api('GET', f'/repos/{repo}/actions/secrets/public-key', token)
    if status != 200:
        raise RuntimeError(f'GET public-key for {repo} failed ({status}): {data}')
    return data['key_id'], data['key']


def _encrypt_secret(public_key_b64: str, secret: str) -> str:
    pk = PublicKey(base64.b64decode(public_key_b64))
    box = SealedBox(pk)
    encrypted = box.encrypt(secret.encode(), encoder=Base64Encoder)
    return encrypted.decode()


def _put_secret(repo: str, name: str, value: str, token: str):
    key_id, pub_key = _get_repo_public_key(repo, token)
    encrypted = _encrypt_secret(pub_key, value)
    status, data = _api(
        'PUT',
        f'/repos/{repo}/actions/secrets/{name}',
        token,
        {'encrypted_value': encrypted, 'key_id': key_id},
    )
    if status not in (201, 204):
        raise RuntimeError(f'PUT secret {name} in {repo} failed ({status}): {data}')


def _put_variable(repo: str, name: str, value: str, token: str):
    # Try update first (PATCH), then create (POST) if not found
    status, data = _api('PATCH', f'/repos/{repo}/actions/variables/{name}', token,
                        {'name': name, 'value': value})
    if status == 404:
        status, data = _api('POST', f'/repos/{repo}/actions/variables', token,
                             {'name': name, 'value': value})
    if status not in (200, 201, 204):
        raise RuntimeError(f'PUT variable {name} in {repo} failed ({status}): {data}')


# ---------------------------------------------------------------------------
# Provisioning logic
# ---------------------------------------------------------------------------
def _load_template():
    for path in TEMPLATE_PATHS:
        p = os.path.normpath(path)
        if os.path.isfile(p):
            with open(p) as f:
                return f.read()
    raise FileNotFoundError(
        f'scan.yml template not found. Searched: {TEMPLATE_PATHS}'
    )


def provision_repo(repo: str, install_token: str, app_id: str, private_key: str):
    print(f'  → Provisioning {repo}')

    template = _load_template()

    # 1. Push workflow file (idempotent)
    sha, exists = _get_file_sha(repo, WORKFLOW_DEST, install_token)
    action = 'Update' if exists else 'Add'
    _put_file(
        repo,
        WORKFLOW_DEST,
        template,
        install_token,
        message=f'ci: {action} ez-appsec security scan workflow',
        sha=sha,
    )
    print(f'    ✓ {"Updated" if exists else "Created"} {WORKFLOW_DEST}')

    # 2. Set secrets
    _put_secret(repo, 'EZ_APPSEC_APP_ID', app_id, install_token)
    print(f'    ✓ Set secret EZ_APPSEC_APP_ID')

    _put_secret(repo, 'EZ_APPSEC_PRIVATE_KEY', private_key, install_token)
    print(f'    ✓ Set secret EZ_APPSEC_PRIVATE_KEY')

    # 3. Set variable
    _put_variable(repo, 'EZ_APPSEC_DASHBOARD_REPO', DASHBOARD_REPO, install_token)
    print(f'    ✓ Set variable EZ_APPSEC_DASHBOARD_REPO={DASHBOARD_REPO}')


def main():
    parser = argparse.ArgumentParser(description='Provision ez-appsec into customer repos')
    parser.add_argument('--token', required=True, help='GitHub App installation token')
    parser.add_argument('--repos', required=True,
                        help='Comma-separated list of owner/repo targets')
    parser.add_argument('--app-id', required=True, help='Numeric GitHub App ID')
    parser.add_argument('--private-key', required=True,
                        help='PEM private key content or path to .pem file')
    args = parser.parse_args()

    # Accept PEM as file path or raw content
    if args.private_key.strip().startswith('-----'):
        private_key = args.private_key
    else:
        with open(args.private_key) as f:
            private_key = f.read()

    repos = [r.strip() for r in args.repos.split(',') if r.strip()]
    if not repos:
        print('No repos specified.', file=sys.stderr)
        sys.exit(1)

    errors = []
    for repo in repos:
        try:
            provision_repo(repo, args.token, args.app_id, private_key)
        except Exception as exc:
            print(f'  ✗ Failed to provision {repo}: {exc}', file=sys.stderr)
            errors.append(repo)

    if errors:
        print(f'\nFailed to provision: {", ".join(errors)}', file=sys.stderr)
        sys.exit(1)

    print(f'\nProvisioned {len(repos)} repo(s) successfully.')


if __name__ == '__main__':
    main()
