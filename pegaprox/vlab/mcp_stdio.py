#!/usr/bin/env python3
"""MOAVI Desk MCP - stdio bridge, for an MCP client that can only start a local program.

It reads JSON-RPC messages from stdin (one per line), sends each to the MOAVI Desk MCP server and
writes the answers to stdout. Python 3.8+, standard library only.

  MOAVI_MCP_URL     https://moavi.example.com/api/vlab/mcp
  MOAVI_MCP_TOKEN   mcp_... (플랫폼 설정 > MCP 연동)
  MOAVI_MCP_CA      optional: the CA certificate (PEM) of a private certificate
  MOAVI_MCP_INSECURE=1  optional: do not check the certificate (test servers only)

  {"mcpServers": {"moavi": {"command": "python3", "args": ["moavi_mcp_stdio.py"],
                            "env": {"MOAVI_MCP_URL": "...", "MOAVI_MCP_TOKEN": "mcp_..."}}}}
"""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request


def _context():
    if os.environ.get('MOAVI_MCP_INSECURE') == '1':
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context(cafile=os.environ.get('MOAVI_MCP_CA') or None)


def _error(mid, message):
    return {'jsonrpc': '2.0', 'id': mid, 'error': {'code': -32000, 'message': message}}


def main():
    url, token = os.environ.get('MOAVI_MCP_URL', ''), os.environ.get('MOAVI_MCP_TOKEN', '')
    if not url or not token:
        sys.stderr.write('MOAVI_MCP_URL and MOAVI_MCP_TOKEN are required\n')
        return 2
    ctx = _context() if url.startswith('https:') else None
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
               'Authorization': f'Bearer {token}'}
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            mid = json.loads(line).get('id')
        except (ValueError, AttributeError):
            mid = None
        req = urllib.request.Request(url, data=line.encode(), headers=headers, method='POST')
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=300) as r:
                body = r.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            text = e.read().decode('utf-8', 'replace')
            try:
                msg = json.loads(text).get('error') or text
            except (ValueError, AttributeError):
                msg = text
            body = json.dumps(_error(mid, f'HTTP {e.code}: {msg}')) if mid is not None else ''
        except (urllib.error.URLError, OSError) as e:
            body = json.dumps(_error(mid, f'MOAVI Desk unreachable: {e}')) if mid is not None else ''
        if body.strip():
            sys.stdout.write(json.dumps(json.loads(body), ensure_ascii=False) + '\n')
            sys.stdout.flush()
    return 0


if __name__ == '__main__':
    sys.exit(main())
