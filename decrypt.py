# -*- coding: utf-8 -*-
# python3.7
# supported xmanager version <5.1, 5.1, 5.2, 6

import os
import argparse
import base64
import configparser

from win32api import GetComputerName, GetUserName
from win32security import LookupAccountName, ConvertSidToStringSid
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import ARC4

def decrypt_string(a1, a2):
    v1 = base64.b64decode(a2)
    v3 = ARC4.new(SHA256.new(a1.encode('ascii')).digest()).decrypt(v1[:len(v1) - 0x20])
    if SHA256.new(v3).digest() == v1[-32:]:
        return v3.decode('ascii')
    else:
        return None

def decrypt_dir():
    for root, dirs, files in os.walk(args.path):
        for f in files:
            if f.endswith(".xsh") or f.endswith(".xfp"):
                filepath = os.path.join(root, f)
                cfg = configparser.ConfigParser()
                try:
                    cfg.read(filepath)
                except UnicodeDecodeError:
                    cfg.read(filepath, encoding="utf-16")

                try:
                    if f.endswith(".xsh"):
                        host = cfg["CONNECTION"]["Host"]
                        port = cfg["CONNECTION"]["Port"]
                        username = cfg["CONNECTION:AUTHENTICATION"]["UserName"]
                        password = cfg["CONNECTION:AUTHENTICATION"]["Password"]
                        version = cfg["SessionInfo"]["Version"]

                        password = decrypt_string(args.sid, password)
                    else:
                        host = cfg["Connection"]["Host"]
                        port = cfg["Connection"]["Port"]
                        username = cfg["Connection"]["UserName"]
                        password = cfg["Connection"]["Password"]
                        version = cfg["SessionInfo"]["Version"]

                        password = decrypt_string(args.sid, password)

                    print(f"{filepath:=^100}")
                    print('%-10s : %s' % ('Host', host))
                    print('%-10s : %s' % ('Port', port))
                    print('%-10s : %s' % ('Version', version))
                    print('%-10s : %s' % ('UserName', username))
                    print('%-10s : %s' % ('Password', password))
                except Exception as e:
                    print(f"{filepath:=^100}\nError:{e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="xsh, xfp password decrypt")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-e", "--encrypt", default=False,
                       help="encrypt password", action="store_true")
    group.add_argument("-d", "--decrypt", default=True,
                       help="decrypt encrypted password", action="store_true")
    parser.add_argument("-u", "--username", default="", type=str,
                        help="user `whoami /user` in command.")
    parser.add_argument("-s", "--sid", default="", type=str,
                        help="SID `whoami /user` in command.")
    parser.add_argument("-v", "--version", default="", type=str,
                        help="xsh or xfp version")
    parser.add_argument("-k", "--key", default="", nargs='?',
                        help="the path of sessions directory or file, or password or other key")

    args = parser.parse_args()
    print(args)
    if not args.sid:
        args.sid = ConvertSidToStringSid(LookupAccountName(GetComputerName(), GetUserName())[0])
    if not args.key:
        # args.key = os.path.join(os.environ["USERPROFILE"], r"Documents\NetSarang Computer\6")
        args.key = os.path.join(os.environ["USERPROFILE"], r"Documents\NetSarang\Xshell\Sessions")

    if not os.path.isdir(args.key):
        r = decrypt_string(args.sid, args.key)
        if r:
            print(r)