#!/usr/bin/env python
# -*- coding: utf-8 -*-

from prettytable import PrettyTable

def print_user_table(users):
        pt = PrettyTable()
        pt.add_column("User", [user[0] for user in users])
        print pt

def print_group_table(groups):
        pt = PrettyTable()
        pt.add_column("Group", [group[0] for group in groups])
        print pt

def print_user_groups_table(user_group_pairs):
        pt = PrettyTable(["User", "Group"])
        for pair in user_group_pairs:
                pt.add_row(pair)
        print pt

def print_group_users_table(group_user_pairs):
        pt = PrettyTable(["Group", "User"])
        for pair in group_user_pairs:
                pt.add_row(pair)
        print pt

if __name__ == '__main__':
        print_user_table(["user1", "user2"])
        print_group_table(["group1", "group2"])
        print_user_groups_table([["user1", "group1,group2"], ["user2", "group2"]])
        print_group_users_table([["group1", "user1,user2"], ["group2", "user2"]])
