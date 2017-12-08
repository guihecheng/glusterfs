#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import shutil
import xml.etree.cElementTree as etree

from utils import execute, cache_output

logger = logging.getLogger()

class Node:
        def __init__(self, uuid, hostname):
                self.uuid = uuid
                self.hostname = hostname
                self.is_local = hostname == "localhost"
@cache_output
def self_uuid():
        cmd = ["gluster", "system::", "uuid", "get", "--xml"]
        rc, out, err = execute(cmd)

        if rc != 0:
                return None

        tree = etree.fromstring(out)
        uuid_el = tree.find("uuidGenerate/uuid")
        return uuid_el.text

def cluster_get_nodes(logger):
        cmd = ["gluster", "pool", "list", "--xml"]
        _, data, _ = execute(cmd, exit_msg="Failed to run gluster pool list", logger=logger)
        tree = etree.fromstring(data)
        opRet_el = tree.find('opRet')
        if int(opRet_el.text) != 0:
                fail("Unable to get pool list", logger=logger)

        nodes = []
        peerStatus_el = tree.find('peerStatus')
        try:
                for peer in peerStatus_el.findall('peer'):
                        node = Node(peer.find('uuid').text, peer.find('hostname').text)
                        nodes.append(node)
        except (ParseError, AttributeError, ValueError) as e:
                fail("Failed to parse peer info %s" % e, logger=logger)

        return nodes

def print_nodes(nodes):
        for n in nodes:
                print "UUID: %s Hostname: %s Local: %s" % (n.uuid, n.hostname, n.is_local)

if __name__ == '__main__':
       nodes =  cluster_get_nodes(logger)
       print_nodes(nodes)
