#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import commands
from sets import Set
from argparse import ArgumentParser, RawDescriptionHelpFormatter

from data import UGRecord, print_ugrecords, extract_ugdata

class LocalCtl:
        def __init__(self):
                pass

        def user_add(self, user, passwd):
                cmd = "useradd " + user
                ret, out = commands.getstatusoutput(cmd)
                if ret:
                        return ret, out

                cmd = "echo " + passwd + " | passwd --stdin " + user
                ret, out = commands.getstatusoutput(cmd)
                return ret, out

        def user_del(self, user):
                cmd = "userdel " + user
                ret, out = commands.getstatusoutput(cmd)
                return ret, out

        def user_passwd(self, user, passwd):
                cmd = "echo " + passwd + " | passwd --stdin " + user
                ret, out = commands.getstatusoutput(cmd)
                return ret, out

        def group_add(self, group):
                cmd = "groupadd " + group
                ret, out = commands.getstatusoutput(cmd)
                return ret, out

        def group_del(self, group):
                cmd = "groupdel " + group
                ret, out = commands.getstatusoutput(cmd)
                return ret, out

        def group_include_user(self, group, user):
                cmd = "gpasswd -a " + user + " " + group
                ret, out = commands.getstatusoutput(cmd)
                return ret, out

        def group_exclude_user(self, group, user):
                cmd = "gpasswd -d " + user + " " + group
                ret, out = commands.getstatusoutput(cmd)
                return ret, out

class SambaCtl:
        def __init__(self):
                pass

        def smb_user_add(self, user, passwd):
                cmd = "echo -e \"" + passwd + "\n" + passwd + "\n\"" + " | smbpasswd -a " + user
                ret, out = commands.getstatusoutput(cmd)
                return ret, out

        def smb_user_del(self, user):
                cmd = "smbpasswd -x " + user
                ret, out = commands.getstatusoutput(cmd)
                return ret, out

        def smb_user_passwd(self, user, passwd):
                cmd = "echo -e \"" + passwd + "\n" + passwd + "\n\"" + " | smbpasswd " + user
                ret, out = commands.getstatusoutput(cmd)
                return ret, out

        def smb_reconfig(self):
                cmd = "systemctl restart smb"
                ret, out = commands.getstatusoutput(cmd)
                if ret:
                        return ret, out

                cmd = "systemctl restart nmb"
                ret, out = commands.getstatusoutput(cmd)
                if ret:
                        return ret, out

def samba_ctl_config_local(groups, ugrecords):
        localctl = LocalCtl()
        for group in groups:
                localctl.group_add(group)

        for record in ugrecords:
                localctl.user_add(record.user, record.passwd)
                for group in record.groups:
                        localctl.group_include_user(group, record.user)

def samba_ctl_drop_local(groups, ugrecords):
        localctl = LocalCtl()
        for record in ugrecords:
                for group in record.groups:
                        localctl.group_exclude_user(group, record.user)
                localctl.user_del(record.user)

        for group in groups:
                localctl.group_del(group)


def samba_ctl_config_samba(ugrecords):
        sambactl = SambaCtl()
        for record in ugrecords:
                sambactl.smb_user_add(record.user, record.passwd)
#        sambactl.smb_reconfig()

def samba_ctl_drop_samba(ugrecords):
        sambactl = SambaCtl()
        for record in ugrecords:
                sambactl.smb_user_del(record.user)
#        sambactl.smb_reconfig()

def samba_ctl_push(filetopush):
	groups, ugrecords = extract_ugdata(filetopush)
#	print_ugrecords(groups, ugrecords)
	samba_ctl_config_local(groups, ugrecords)
	samba_ctl_config_samba(ugrecords)

def samba_ctl_drop(filetodrop):
	groups, ugrecords = extract_ugdata(filetodrop)
#	print_ugrecords(groups, ugrecords)
	samba_ctl_drop_samba(ugrecords)
	samba_ctl_drop_local(groups, ugrecords)

def _get_args():
        parser = ArgumentParser(formatter_class = RawDescriptionHelpFormatter,
                                description = "Samba Local User Group Control Tool")
        subparsers = parser.add_subparsers(dest = "subcommand")

        parser_user = subparsers.add_parser("user", help = "user operation")
        user_subparsers = parser_user.add_subparsers(dest = "userop")

        parser_user_add = user_subparsers.add_parser("add", help = "user add")
        parser_user_add.add_argument("--user", help = "User name", required = True);
        parser_user_add.add_argument("--passwd", help = "User password", required = True);

        parser_user_del = user_subparsers.add_parser("del", help = "user del")
        parser_user_del.add_argument("--user", help = "User name", required = True);

        parser_user_passwd = user_subparsers.add_parser("passwd", help = "user change passwd")
        parser_user_passwd.add_argument("--user", help = "User name", required = True);
        parser_user_passwd.add_argument("--passwd", help = "User password", required = True);

        parser_group = subparsers.add_parser("group", help = "group operation")
        group_subparsers = parser_group.add_subparsers(dest = "groupop")

        parser_group_add = group_subparsers.add_parser("add", help = "group add")
        parser_group_add.add_argument("--group", help = "Group name", required = True);

        parser_group_del = group_subparsers.add_parser("del", help = "group del")
        parser_group_del.add_argument("--group", help = "Group name", required = True);

        parser_group_include = group_subparsers.add_parser("include", help = "group include user")
        parser_group_include.add_argument("--group", help = "Group name", required = True);
        parser_group_include.add_argument("--user", help = "User name", required = True);

        parser_group_exclude = group_subparsers.add_parser("exclude", help = "group exclude user")
        parser_group_exclude.add_argument("--group", help = "Group name", required = True);
        parser_group_exclude.add_argument("--user", help = "User name", required = True);

        parser_batch = subparsers.add_parser("batch", help = "batch user&group operation")
        batch_subparsers = parser_batch.add_subparsers(dest = "batchop")

        parser_batch_push = batch_subparsers.add_parser("push", help = "push user&group data")
        parser_batch_push.add_argument("--data", help = "user group data file", required = True);
        parser_batch_drop = batch_subparsers.add_parser("drop", help = "drop user&group data")
        parser_batch_drop.add_argument("--data", help = "user group data file", required = True);

        return parser.parse_args()

if __name__ == '__main__':
        args = _get_args()

        localCtl = LocalCtl()
        sambaCtl = SambaCtl()

        if args.subcommand == "user":
                if args.userop == "add":
                        localCtl.user_add(args.user, args.passwd)
                        sambaCtl.smb_user_add(args.user, args.passwd)
                elif args.userop == "del":
                        localCtl.user_del(args.user)
                        sambaCtl.smb_user_del(args.user)
                elif args.userop == "passwd":
                        localCtl.user_passwd(args.user, args.passwd)
                        sambaCtl.smb_user_passwd(args.user, args.passwd)
                else:
                        print "Unknown User Operation"
                        sys.exit(1)
#                sambaCtl.smb_reconfig()
        elif args.subcommand == "group":
                if args.groupop == "add":
                        localCtl.group_add(args.group)
                elif args.groupop == "del":
                        localCtl.group_del(args.group)
                elif args.groupop == "include":
                        localCtl.group_include_user(args.group, args.user)
                elif args.groupop == "exclude":
                        localCtl.group_exclude_user(args.group, args.user)
                else:
                        print "Unknown Group Operation"
                        sys.exit(2)
        elif args.subcommand == "batch":
                if args.batchop == "push":
                        samba_ctl_push(args.data)
                elif args.batchop == "drop":
                        samba_ctl_drop(args.data)
                else:
                        print "Unknown Batch Operation"
                        sys.exit(3)
        else:
                print "Unknown Command"
                sys.exit(4)
