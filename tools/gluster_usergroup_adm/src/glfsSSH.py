#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import shutil
import xml.etree.cElementTree as etree
from multiprocessing import Process

import conf
from utils import execute, mkdirp, fail

from cluster import self_uuid, cluster_get_nodes

FILE_DESTINATION = "/var/lib/glusterd/gluster_usergroup_adm"

class GlfsSSH:
        def __init__(self, node_uuid, logger):
                self.node_uuid = node_uuid
                self.pem_key_path = os.path.join(conf.get_opt("working_dir"), "%s_secret.pem" % node_uuid)
                self.logger = logger

        def gen_key(self):
                if os.path.exists(self.pem_key_path):
                        return

                cmd = ["ssh-keygen", "-N", "", "-f", self.pem_key_path]
                execute(cmd, exit_msg="Unable to generate ssh key %s" % self.pem_key_path, logger=self.logger)

                self.logger.info("Ssh Key generated %s" % self.pem_key_path)

        def copy_keys(self):
                try:
                        shutil.copyfile(self.pem_key_path + ".pub", os.path.join(FILE_DESTINATION, ".keys", "%s_secret.pem.pub" % self.node_uuid))
                except (IOError, OSError) as e:
                        fail("Failed to copy public key to %s: %s" % os.path.join(FILE_DESTINATION, ".keys"), e, logger=self.logger)

        def auth_nodes(self):
                cmd = ["gluster", "system::", "copy", "file", "/gluster_usergroup_adm/.keys/%s.pub" % os.path.basename(self.pem_key_path)]
                execute(cmd, exit_msg="Failed to distribute ssh keys", logger=self.logger)

                self.logger.info("Distributed ssh key to all nodes")

                cmd = ["gluster", "system::", "execute", "add_secret_pub", "root", "/gluster_usergroup_adm/.keys/%s.pub" % os.path.basename(self.pem_key_path)]
                execute(cmd, exit_msg="Failed to add ssh keys to authorized_keys file", logger=self.logger)

                self.logger.info("Ssh key added to authorized_keys")

        def ssh_setup(self):
                self.gen_key()
                self.copy_keys()
                self.auth_nodes()

        def ssh_send_cmd(self, node, cmd):
                try:
                        if not node.is_local:
                                cmd = ["ssh", "-oNumberOfPasswordPrompts=0", "-oStrictHostKeyChecking=no", "-t", "-i", self.pem_key_path,
                                       "root@%s" % node.hostname ] + cmd
                        execute(cmd, exit_msg="%s execute failed" % node.hostname, logger=self.logger)
                except KeyboardInterrupt:
                        sys.exit(2)

        def ssh_send_scp(self, filetosend):
                try:
                        cmd = ["gluster", "system::", "copy", "file", "/gluster_usergroup_adm/%s" % os.path.basename(filetosend)]
                        execute(cmd, exit_msg="Failed to copy file, please ensure %s has your file" % FILE_DESTINATION, logger=self.logger)
                except KeyboardInterrupt:
                        sys.exit(2)
                pass

        def ssh_recv_ret(self):
                pass

def enable_password_less_ssh(logger):
        glfsSSH = GlfsSSH(self_uuid(), logger)
        glfsSSH.ssh_setup()

def run_cluster_cmd(cmd, logger):
        glfsSSH = GlfsSSH(self_uuid(), logger)
        nodes = cluster_get_nodes(logger)
        pool = []
        for num, node in enumerate(nodes):
               p = Process(target=glfsSSH.ssh_send_cmd, args=(node, cmd))
               p.start()
               pool.append(p)

        for num, p in enumerate(pool):
                p.join()
                if p.exitcode != 0:
                        logger.warn("Command %s failed in %s" % (cmd, nodes[num].hostname))

def run_cluster_copy(filetocopy, logger):
        shutil.copyfile(filetocopy, os.path.join(FILE_DESTINATION, os.path.basename(filetocopy)))
        glfsSSH = GlfsSSH(self_uuid(), logger)
        glfsSSH.ssh_send_scp(filetocopy)
