#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3

from data import UGRecord, extract_ugdata

"""
Table Users
        ID  | Name | Password

Table Groups
        ID  | Name

Table GroupBelongs
        ID  | UID  | GID
"""

class DBStore:
        def __init__(self, backendfile):
                self.backend = backendfile

        def create_tables(self):
                cur = self.conn.cursor()

                cur.execute('''
                            DROP TABLE IF EXISTS users;
                            ''')
                cur.execute('''
                            DROP TABLE IF EXISTS groups;
                            ''')
                cur.execute('''
                            DROP TABLE IF EXISTS groupbelongs;
                            ''')
                cur.execute('''
                            CREATE TABLE users (
                              id integer primary key,
                              name varchar unique,
                              passwd text not null
                            );
                            ''')
                cur.execute('''
                            CREATE TABLE groups (
                              id integer primary key,
                              name varchar unique
                            );
                            ''')
                cur.execute('''
                            CREATE TABLE groupbelongs (
                              id integer primary key,
                              uname varchar not null,
                              gname varchar not null,
                              unique (uname,gname)
                            );
                            ''')
                self.conn.commit()


        def connect(self):
                self.conn = sqlite3.connect(self.backend)

        def close(self):
               self.conn.close()

        def insert_user(self, user, passwd):
                cur = self.conn.cursor()
                cur.execute("INSERT INTO users(name,passwd) values(?,?)", (user, passwd))
                self.conn.commit()

        def delete_user(self, user):
                cur = self.conn.cursor()
                cur.execute("DELETE FROM users where name=?", (user,))
                self.conn.commit()

        def update_user(self, user, passwd):
                cur = self.conn.cursor()
                cur.execute("UPDATE users set passwd=? where name=?", (passwd, user))
                self.conn.commit()

        def insert_group(self, group):
                cur = self.conn.cursor()
                cur.execute("INSERT INTO groups(name) values(?)", (group,))
                self.conn.commit()

        def delete_group(self, group):
                cur = self.conn.cursor()
                cur.execute("DELETE FROM groups where name=?", (group,))
                self.conn.commit()

        def group_include_user(self, group, user):
                cur = self.conn.cursor()
                cur.execute("INSERT INTO groupbelongs(uname,gname) values(?,?)", (user, group))
                self.conn.commit()

        def group_exclude_user(self, group, user):
                cur = self.conn.cursor()
                cur.execute("DELETE FROM groupbelongs where uname=? and gname=?", (user, group))
                self.conn.commit()

        def batch_push(self, ugdata_file):
                groups, ugrecords = extract_ugdata(ugdata_file)

                push_groups = [(group,) for group in groups]
                push_users = [(rec.user, rec.passwd) for rec in ugrecords]
                push_belongs = [ (rec.user, group) for rec in ugrecords for group in rec.groups ]

                cur = self.conn.cursor()
                cur.executemany("INSERT INTO groups(name) values(?)", push_groups)
                cur.executemany("INSERT INTO users(name,passwd) values(?,?)", push_users)
                cur.executemany("INSERT INTO groupbelongs(uname,gname) values(?,?)", push_belongs)
                self.conn.commit()

        def batch_drop(self, ugdata_file):
                groups, ugrecords = extract_ugdata(ugdata_file)

                drop_groups = [(group,) for group in groups]
                drop_users = [(rec.user,) for rec in ugrecords]
                drop_belongs = [ (rec.user, group) for rec in ugrecords for group in rec.groups ]

                cur = self.conn.cursor()
                cur.executemany("DELETE FROM groupbelongs where uname=? and gname=?", drop_belongs)
                cur.executemany("DELETE FROM users where name=?", drop_users)
                cur.executemany("DELETE FROM groups where name=?", drop_groups)
                self.conn.commit()

        def show_users(self):
                cur = self.conn.cursor()
                cur.execute("SELECT name FROM users")
                users = cur.fetchall()
                return users

        def show_groups(self):
                cur = self.conn.cursor()
                cur.execute("SELECT name FROM groups")
                groups = cur.fetchall()
                return groups

        def show_belongs(self):
                cur = self.conn.cursor()
                cur.execute("SELECT uname,gname FROM groupbelongs")
                groupbelongs = cur.fetchall()
                return groupbelongs

        def show_user_groups(self, user):
                cur = self.conn.cursor()
                cur.execute("SELECT gname FROM groupbelongs where uname=?", (user,))
                groups = cur.fetchall()
                return groups

        def show_group_users(self, group):
                cur = self.conn.cursor()
                cur.execute("SELECT uname FROM groupbelongs where gname=?", (group,))
                users = cur.fetchall()
                return users

        def show_user_groups_all(self):
                cur = self.conn.cursor()
                cur.execute("SELECT uname,group_concat(gname) FROM groupbelongs group by uname")
                user_groups = cur.fetchall()
                return user_groups

        def show_group_users_all(self):
                cur = self.conn.cursor()
                cur.execute("SELECT gname,group_concat(uname) FROM groupbelongs group by gname")
                group_users = cur.fetchall()
                return group_users

if __name__ == '__main__':
       db = DBStore("./ugdata.db")
       db.connect()
       db.create_tables()
       db.insert_group("group1")
       db.insert_group("group2")
       db.insert_user("user1", "123123")
       db.insert_user("user2", "123123")
       db.update_user("user1", "123")
       db.group_include_user("group1", "user1")
       db.group_include_user("group1", "user2")
       db.group_include_user("group2", "user2")
       print db.show_users()
       print db.show_groups()
       print db.show_belongs()
       print db.show_user_groups("user1")
       print db.show_group_users("group1")
       print db.show_user_groups_all()
       print db.show_group_users_all()
       db.group_exclude_user("group2", "user2")
       db.group_exclude_user("group1", "user2")
       db.group_exclude_user("group1", "user1")
       db.delete_user("user2")
       db.delete_user("user1")
       db.delete_group("group2")
       db.delete_group("group1")
       print db.show_users()
       print db.show_groups()
       print db.show_belongs()
       db.close()
