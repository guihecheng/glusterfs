#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sets import Set

class UGRecord:
        def __init__(self, user, passwd, groups):
                self.user = user
                self.passwd = passwd
                self.groups = groups.split(',')

def print_ugrecords(groups, ugrecords):
	for g in groups:
		print g
	for ug in ugrecords:
		print ug.user
		print ug.passwd
		for g in ug.groups:
			print g

def extract_ugdata(ugdata_file):
        ugrecords = []
        groups = Set([])
        with open(ugdata_file, "r") as ugdata:
                for line in ugdata:
                        if not len(line.strip()) or line.startswith('#'):
                                continue
                        record = UGRecord(line.strip().split(':')[0],
                                          line.strip().split(':')[1],
                                          line.strip().split(':')[2])
                        ugrecords.append(record)

                        for group in record.groups:
                                groups.add(group)

        return groups, ugrecords
