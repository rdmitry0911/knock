#!/usr/bin/python3
"""CLI using the same saved profile and transport as the browser extension."""
import argparse
import getpass
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import native
from common import client_bundle, read_json

parser = argparse.ArgumentParser(description='Knock Control TOTP client')
parser.add_argument('action', choices=['open','close'])
parser.add_argument('--profile', type=Path, help='Server-issued client file (otherwise use selected imported profile)')
parser.add_argument('--ask-code', action='store_true', help='Prompt for a Google Authenticator code')
args = parser.parse_args()
try:
    bundle = client_bundle(read_json(args.profile)) if args.profile else native.active_profile(native.store_load())
    cfg = native.transport_config(bundle)
    code = getpass.getpass('Google Authenticator code: ') if args.ask_code else None
    print(json.dumps(native.knock(cfg,args.action,code),ensure_ascii=False))
except (ValueError,OSError) as error:
    parser.exit(1,str(error)+'\n')
