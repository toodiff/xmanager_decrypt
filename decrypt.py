# -*- coding: utf-8 -*-
# python >= 3.7
# supported xmanager version <5.1, 5.1, 5.2, 6

import os
import argparse
import configparser
import unicodedata

from win32api import GetComputerName, GetUserName
from win32security import LookupAccountName, ConvertSidToStringSid
from base64 import b64encode, b64decode
from Cryptodome.Hash import MD5, SHA256
from Cryptodome.Cipher import ARC4

USERNAME   = GetUserName()
MASTER_PWD = None
SID        = ConvertSidToStringSid(LookupAccountName(GetComputerName(), GetUserName())[0])
IS_XSH     = True
VERSION    = '5.2'
KEY        = os.path.join(os.environ["USERPROFILE"], r"Documents\NetSarang\Xshell\Sessions")
IS_DECRYPT = True

def getCipherKey():
    if not is_number(VERSION):
        raise ValueError('Invalid argument: --Version')

    ver = float(VERSION)
    if 0 < ver and ver < 5.1:
        if IS_XSH:
            return MD5.new(b'!X@s#h$e%l^l&').digest()
        else:
            return MD5.new(b'!X@s#c$e%l^l&').digest()
    elif 5.1 <= ver and ver <= 5.2:
        return SHA256.new(SID.encode()).digest()
    elif 5.2 < ver:
        if MASTER_PWD == None:
            return SHA256.new((USERNAME + SID).encode()).digest()
        else:
            return SHA256.new(MASTER_PWD.encode()).digest()
    else:
        raise ValueError('Invalid argument: --Version')

def encrypt_string(password_string, need_return=False):
    if not is_number(VERSION):
        raise ValueError('Invalid argument: --Version')

    ver = float(VERSION)

    Cipher = ARC4.new(getCipherKey())
    if ver < 5.1:
        en_password = b64encode(Cipher.encrypt(password_string.encode())).decode()
    else:
        checksum = SHA256.new(password_string.encode()).digest()
        ciphertext = Cipher.encrypt(password_string.encode())
        en_password = b64encode(ciphertext + checksum).decode()
    if need_return:
        return en_password
    else:
        print('%-20s : %s' % ('Version', VERSION))
        print('%-20s : %s' % ('UserName', USERNAME))
        print('%-20s : %s' % ('Password', password_string))
        print('%-20s : %s' % ('Encrypted Password', en_password))

def decrypt_string(password_string, need_return=False):
    if not is_number(VERSION):
        raise ValueError('Invalid argument: --Version')

    ver = float(VERSION)

    Cipher = ARC4.new(getCipherKey())

    try:
        if ver < 5.1:
            de_password = Cipher.decrypt(b64decode(password_string)).decode()
        else:
            data = b64decode(password_string)
            ciphertext, checksum = data[:-SHA256.digest_size], data[-SHA256.digest_size:]
            plaintext = Cipher.decrypt(ciphertext)
            if SHA256.new(plaintext).digest() != checksum:
                raise ValueError('Cannot decrypt string. The key is wrong!')
            de_password = plaintext.decode('ascii')
        if need_return:
            return de_password
        else:
            print('%-20s : %s' % ('Version', VERSION))
            print('%-20s : %s' % ('UserName', USERNAME))
            print('%-20s : %s' % ('Password', password_string))
            print('%-20s : %s' % ('Decrypted Password', de_password))

    except Exception as e:
        print(f"Password is invalid")

def decrypt_file(filepath: str = ''):
    if not os.path.isfile(filepath):
        print(f"{filepath:=^100}\nError: No file")
        return

    file = os.path.basename(os.path.realpath(filepath))

    if file.endswith(".xsh") or file.endswith(".xfp"):
        cfg = configparser.ConfigParser()
        try:
            cfg.read(filepath)
        except UnicodeDecodeError:
            cfg.read(filepath, encoding="utf-16")

        try:
            if file.endswith(".xsh"):
                host = cfg["CONNECTION"]["Host"]
                port = cfg["CONNECTION"]["Port"]
                username = cfg["CONNECTION:AUTHENTICATION"]["UserName"]
                password = cfg["CONNECTION:AUTHENTICATION"]["Password"]
                version = cfg["SessionInfo"]["Version"]

                de_password = decrypt_string(password, True)
            else:
                host = cfg["Connection"]["Host"]
                port = cfg["Connection"]["Port"]
                username = cfg["Connection"]["UserName"]
                password = cfg["Connection"]["Password"]
                version = cfg["SessionInfo"]["Version"]

                de_password = decrypt_string(password, True)

            print(f"{filepath:=^100}")
            print('%-20s : %s' % ('Host', host))
            print('%-20s : %s' % ('Port', port))
            print('%-20s : %s' % ('Version', version))
            print('%-20s : %s' % ('UserName', username))
            print('%-20s : %s' % ('Password', de_password))
            print('%-20s : %s' % ('Encrypted Password', password))
        except Exception as e:
            print(f"{filepath:=^100}\nError:{e}")

def decrypt_dir():
    for root, dirs, files in os.walk(KEY):
        for f in files:
            decrypt_file(os.path.join(root, f))

def setDefaultSessionDirByVer():
    if not is_number(VERSION):
        return
    ver = float(VERSION)
    dir = 'Xshell' if IS_XSH else 'Xftp';
    global KEY
    if ver < 6:
        KEY = os.path.join(os.environ["USERPROFILE"], r"Documents\NetSarang\%s\Sessions" % dir)
    elif ver == 6:
        KEY = os.path.join(os.environ["USERPROFILE"], r"Documents\NetSarang Computer\6\%s\Sessions" % dir)

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass

    try:
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass

    return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="xsh, xfp password decrypt")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-e", "--encrypt", default=False,
                       help="<-e | -d> encrypt password, default -d", action="store_true")
    group.add_argument("-d", "--decrypt", default=True,
                       help="<-e | -d> decrypt encrypted password, default -d", action="store_true")
    parser.add_argument("-f", "--ftp", default=False,
                        help="xftp or xshell. Ignore if it is xshell", action="store_true")
    parser.add_argument("-u", "--username", default="", type=str,
                        help="user `whoami /user` in command. Ignore if it is local. Used by version >= 5.1")
    parser.add_argument("-m", "--master_pwd", default="", type=str,
                        help="user\'s master password. Used by version >= 6")
    parser.add_argument("-s", "--sid", default="", type=str,
                        help="SID `whoami /user` in command. Ignore if it is local. Used by version >= 5.1")
    parser.add_argument("-v", "--version", default="", type=str,
                        help="xsh or xfp version. If not specified, 5.2 will be used.")
    parser.add_argument("-k", "--key", default="", nargs='?',
                        help="the path of sessions directory or file of xsh or xfp, or password or other key")

    args = parser.parse_args()

    #print(args)

    if args.encrypt:
        IS_DECRYPT = False
    if args.sid:
        SID = args.sid
    if args.username:
        USERNAME = args.username
    if args.master_pwd:
        MASTER_PWD = args.master_pwd
    if args.ftp:
        IS_XSH = False
    if is_number(args.version):
        VERSION = args.version
    if args.key:
        KEY = args.key

    if not args.key and (is_number(args.version) or args.ftp):
        setDefaultSessionDirByVer()

    if IS_DECRYPT:
        if os.path.isdir(KEY):
            decrypt_dir()
        elif os.path.isfile(KEY):
            decrypt_file(KEY)
        else:
            decrypt_string(KEY)
    else:
        encrypt_string(KEY)