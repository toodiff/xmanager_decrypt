# xmanager_decrypt
supported xmanage 5.1, 5.2 and 6

##1. First
Make sure that you have installed Python >= 3.7.

Make sure that you have installed pypiwin32, pycryptodome module.

##2. Help
```
$ python decrypt.py -h

usage: decrypt.py [-h] [-e | -d] [-f] [-u USERNAME] [-m MASTER_PWD] [-s SID]
                  [-v VERSION] [-k [KEY]]

xsh, xfp password decrypt

optional arguments:
  -h, --help            show this help message and exit
  -e, --encrypt         <-e | -d> encrypt password, default -d
  -d, --decrypt         <-e | -d> decrypt encrypted password, default -d
  -f, --ftp             xftp or xshell. Ignore if it is xshell
  -u USERNAME, --username USERNAME
                        user `whoami /user` in command. Ignore if it is local.
                        Used by version >= 5.1
  -m MASTER_PWD, --master_pwd MASTER_PWD
                        user's master password. Used by version >= 6
  -s SID, --sid SID     SID `whoami /user` in command. Ignore if it is local.
                        Used by version >= 5.1
  -v VERSION, --version VERSION
                        xsh or xfp version. If not specified, 5.2 will be
                        used.
  -k [KEY], --key [KEY]
                        the path of sessions directory or file of xsh or xfp,
                        or password or other key

```

##3. Usage
###3.1 if xmanage is used by local machine and current user

if it's version is 5.2, run it simply as below
```
$ python decrypt.py
```
if it's version is not 5.2, run it simply as below, please specify {version}
```
$ python decrypt.py -v {version}
```