#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import logging
from argparse import ArgumentParser, RawDescriptionHelpFormatter

import conf
from utils import mkdirp, setup_logger
from glfsSSH import enable_password_less_ssh, run_cluster_cmd, run_cluster_copy, FILE_DESTINATION
from store import DBStore
import output

logger = logging.getLogger()
dbstore = DBStore(conf.get_opt("db_file"))

def _get_args():
        parser = ArgumentParser(formatter_class = RawDescriptionHelpFormatter,
                                description = "Gluster User Group Administration Tool")

        subparsers = parser.add_subparsers(dest = "subcommand")

        parser_init_db = subparsers.add_parser("init-db", help = "setup local database")
        parser_init_ssh = subparsers.add_parser("init-ssh", help = "setup pasword-less ssh")

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

        parser_user_show = user_subparsers.add_parser("show", help = "user show groups")
        parser_user_show.add_argument("--user", help = "User name", required = True);

        parser_user_list = user_subparsers.add_parser("list", help = "list all users")

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

        parser_group_show = group_subparsers.add_parser("show", help = "group show users")
        parser_group_show.add_argument("--group", help = "Group name", required = True);

        parser_group_list = group_subparsers.add_parser("list", help = "list all groups")

        parser_batch = subparsers.add_parser("batch", help = "batch user&group operation")
        batch_subparsers = parser_batch.add_subparsers(dest = "batchop")

        parser_batch_push = batch_subparsers.add_parser("push", help = "push user&group data")
        parser_batch_push.add_argument("--data", help = "user group data file", required = True);

        parser_batch_drop = batch_subparsers.add_parser("drop", help = "drop user&group data")
        parser_batch_drop.add_argument("--data", help = "user group data file", required = True);

        parser_batch_showUsers = batch_subparsers.add_parser("showUsers", help = "show all users with groups")
        parser_batch_showGroups = batch_subparsers.add_parser("showGroups", help = "show all groups with users")

        return parser.parse_args()

def gluster_user_add(user, passwd):
        cmd = [conf.get_opt("cmd_agent"), "user", "add", "--user", user, "--passwd", passwd]
        run_cluster_cmd(cmd, logger)
        dbstore.insert_user(user, passwd)

def gluster_user_del(user):
        cmd = [conf.get_opt("cmd_agent"), "user", "del", "--user", user]
        run_cluster_cmd(cmd, logger)
        dbstore.delete_user(user)

def gluster_user_passwd(user, passwd):
        cmd = [conf.get_opt("cmd_agent"), "user", "passwd", "--user", user, "--passwd", passwd]
        run_cluster_cmd(cmd, logger)
        dbstore.update_user(user, passwd)

def gluster_user_show_groups(user):
        output.print_user_groups_table([[user, ",".join([group[0] for group in dbstore.show_user_groups(user)])]])

def gluster_user_list():
        output.print_user_table(dbstore.show_users())

def gluster_group_add(group):
        cmd = [conf.get_opt("cmd_agent"), "group", "add", "--group", group]
        run_cluster_cmd(cmd, logger)
        dbstore.insert_group(group)

def gluster_group_del(group):
        cmd = [conf.get_opt("cmd_agent"), "group", "del", "--group", group]
        run_cluster_cmd(cmd, logger)
        dbstore.delete_group(group)

def gluster_group_include_user(group, user):
        cmd = [conf.get_opt("cmd_agent"), "group", "include", "--group", group, "--user", user]
        run_cluster_cmd(cmd, logger)
        dbstore.group_include_user(group, user)

def gluster_group_exclude_user(group, user):
        cmd = [conf.get_opt("cmd_agent"), "group", "exclude", "--group", group, "--user", user]
        run_cluster_cmd(cmd, logger)
        dbstore.group_exclude_user(group, user)

def gluster_group_show_users(group):
        output.print_group_users_table([[group, ",".join([user[0] for user in dbstore.show_group_users(group)])]])

def gluster_group_list():
        output.print_group_table(dbstore.show_groups())

def gluster_batch_push(ugdata_file):
        run_cluster_copy(ugdata_file, logger)
        cmd = [conf.get_opt("cmd_agent"), "batch", "push", "--data", os.path.join(FILE_DESTINATION, os.path.basename(ugdata_file))]
        run_cluster_cmd(cmd, logger)
        dbstore.batch_push(ugdata_file)

def gluster_batch_drop(ugdata_file):
        run_cluster_copy(ugdata_file, logger)
        cmd = [conf.get_opt("cmd_agent"), "batch", "drop", "--data", os.path.join(FILE_DESTINATION, os.path.basename(ugdata_file))]
        run_cluster_cmd(cmd, logger)
        dbstore.batch_drop(ugdata_file)

def gluster_batch_show_users():
        output.print_user_groups_table(dbstore.show_user_groups_all())

def gluster_batch_show_groups():
        output.print_group_users_table(dbstore.show_group_users_all())

def ensure_dirs():
        mkdirp(conf.get_opt("working_dir"))
        mkdirp(os.path.dirname(conf.get_opt("log_file")))

def init_dbstore():
        dbstore.create_tables()

def connect_store():
        dbstore.connect()

def close_store():
        dbstore.close()

def main():
        try:
                args = _get_args()

                ensure_dirs()

                connect_store()

                setup_logger(logger, conf.get_opt("log_file"))

                if args.subcommand == "init-db":
                        init_dbstore()
                elif args.subcommand == "init-ssh":
                        enable_password_less_ssh(logger)
                        sys.exit(0)
                elif args.subcommand == "user":
                        if args.userop == "add":
                                gluster_user_add(args.user, args.passwd)
                        elif args.userop == "del":
                                gluster_user_del(args.user)
                        elif args.userop == "passwd":
                                gluster_user_passwd(args.user, args.passwd)
                        elif args.userop == "show":
                                gluster_user_show_groups(args.user)
                        elif args.userop == "list":
                                gluster_user_list()
                        else:
                                print "Unknown User Operation"
                                sys.exit(1)
                elif args.subcommand == "group":
                        if args.groupop == "add":
                                gluster_group_add(args.group)
                        elif args.groupop == "del":
                                gluster_group_del(args.group)
                        elif args.groupop == "include":
                                gluster_group_include_user(args.group, args.user)
                        elif args.groupop == "exclude":
                                gluster_group_exclude_user(args.group, args.user)
                        elif args.groupop == "show":
                                gluster_group_show_users(args.group)
                        elif args.groupop == "list":
                                gluster_group_list()
                        else:
                                print "Unknown Group Operation"
                                sys.exit(2)
                elif args.subcommand == "batch":
                        if args.batchop == "push":
                                gluster_batch_push(args.data)
                        elif args.batchop == "drop":
                                gluster_batch_drop(args.data)
                        elif args.batchop == "showUsers":
                                gluster_batch_show_users()
                        elif args.batchop == "showGroups":
                                gluster_batch_show_groups()
                        else:
                                print "Unknown Batch Operation"
                                sys.exit(3)
                else:
                        print "Unknown Command"
                        sys.exit(4)
                close_store()
        except KeyboardInterrupt:
                sys.exit(5)

if __name__ == '__main__':
        main()
