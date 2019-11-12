#
# Copyright (c) 2011-2014 Red Hat, Inc. <http://www.redhat.com>
# This file is part of GlusterFS.

# This file is licensed to you under your choice of the GNU Lesser
# General Public License, version 3 or any later version (LGPLv3 or
# later), or the GNU General Public License, version 2 (GPLv2), in all
# cases as published by the Free Software Foundation.
#

import os
import sys
import time
import signal
import logging
import uuid
import xml.etree.ElementTree as XET
from subprocess import PIPE
from resource import FILE, GLUSTER, SSH
from threading import Lock
from errno import ECHILD, ESRCH
import re
import random
from gconf import gconf
from syncdutils import select, waitpid, errno_wrap, lf
from syncdutils import set_term_handler, is_host_local, GsyncdError
from syncdutils import escape, Thread, finalize, boolify
from syncdutils import gf_event, EVENT_GEOREP_FAULTY
from syncdutils import Volinfo, Popen

from gsyncdstatus import GeorepStatus, set_monitor_status
from syncdutils import unshare_propagation_supported

ParseError = XET.ParseError if hasattr(XET, 'ParseError') else SyntaxError


def get_subvol_num(brick_idx, vol, hot):
    tier = vol.is_tier()
    disperse_count = vol.disperse_count(tier, hot)
    replica_count = vol.replica_count(tier, hot)

    if (tier and not hot):
        brick_idx = brick_idx - vol.get_hot_bricks_count(tier)

    subvol_size = disperse_count if disperse_count > 0 else replica_count
    cnt = int((brick_idx + 1) / subvol_size)
    rem = (brick_idx + 1) % subvol_size
    if rem > 0:
        cnt = cnt + 1

    if (tier and hot):
        return "hot_" + str(cnt)
    elif (tier and not hot):
        return "cold_" + str(cnt)
    else:
        return str(cnt)


def get_slave_bricks_status(host, vol):
    po = Popen(['gluster', '--xml', '--remote-host=' + host,
                'volume', 'status', vol, "detail"],
               stdout=PIPE, stderr=PIPE)
    vix = po.stdout.read()
    po.wait()
    po.terminate_geterr(fail_on_err=False)
    if po.returncode != 0:
        logging.info(lf("Volume status command failed, unable to get "
                        "list of up nodes, returning empty list",
                        volume=vol,
                        error=po.returncode))
        return []
    vi = XET.fromstring(vix)
    if vi.find('opRet').text != '0':
        logging.info(lf("Unable to get list of up nodes, "
                        "returning empty list",
                        volume=vol,
                        error=vi.find('opErrstr').text))
        return []

    up_hosts = set()

    try:
        for el in vi.findall('volStatus/volumes/volume/node'):
            if el.find('status').text == '1':
                up_hosts.add(el.find('hostname').text)
    except (ParseError, AttributeError, ValueError) as e:
        logging.info(lf("Parsing failed to get list of up nodes, "
                        "returning empty list",
                        volume=vol,
                        error=e))

    return list(up_hosts)


class Monitor(object):

    """class which spawns and manages gsyncd workers"""

    ST_INIT = 'Initializing...'
    ST_STARTED = 'Started'
    ST_STABLE = 'Active'
    ST_FAULTY = 'Faulty'
    ST_INCON = 'inconsistent'
    _ST_ORD = [ST_STABLE, ST_INIT, ST_FAULTY, ST_INCON]

    def __init__(self):
        self.lock = Lock()
        self.state = {}
        self.status = {}

    @staticmethod
    def terminate():
        # relax one SIGTERM by setting a handler that sets back
        # standard handler
        set_term_handler(lambda *a: set_term_handler())
        # give a chance to graceful exit
        errno_wrap(os.kill, [-os.getpid(), signal.SIGTERM], [ESRCH])

    def monitor(self, w, argv, cpids, agents, slave_vol, slave_host, master):
        """the monitor loop

        Basic logic is a blantantly simple blunt heuristics:
        if spawned client survives 60 secs, it's considered OK.
        This servers us pretty well as it's not vulneralbe to
        any kind of irregular behavior of the child...

        ... well, except for one: if children is hung up on
        waiting for some event, it can survive aeons, still
        will be defunct. So we tweak the above logic to
        expect the worker to send us a signal within 60 secs
        (in the form of closing its end of a pipe). The worker
        does this when it's done with the setup stage
        ready to enter the service loop (note it's the setup
        stage which is vulnerable to hangs -- the full
        blown worker blows up on EPIPE if the net goes down,
        due to the keep-alive thread)
        """
        if not self.status.get(w[0]['dir'], None):
            self.status[w[0]['dir']] = GeorepStatus(gconf.state_file,
                                                    w[0]['host'],
                                                    w[0]['dir'],
                                                    w[0]['uuid'],
                                                    master,
                                                    "%s::%s" % (slave_host,
                                                                slave_vol))

        ret = 0

        def nwait(p, o=0):
            try:
                p2, r = waitpid(p, o)
                if not p2:
                    return
                return r
            except OSError as e:
                # no child process, this happens if the child process
                # already died and has been cleaned up
                if e.errno == ECHILD:
                    return -1
                else:
                    raise

        def exit_signalled(s):
            """ child teminated due to receipt of SIGUSR1 """
            return (os.WIFSIGNALED(s) and (os.WTERMSIG(s) == signal.SIGUSR1))

        def exit_status(s):
            if os.WIFEXITED(s):
                return os.WEXITSTATUS(s)
            return 1

        conn_timeout = int(gconf.connection_timeout)
        while ret in (0, 1):
            remote_host = w[1]
            # Check the status of the connected slave node
            # If the connected slave node is down then try to connect to
            # different up node.
            m = re.match("(ssh|gluster|file):\/\/(.+)@([^:]+):(.+)",
                         remote_host)
            if m:
                current_slave_host = m.group(3)
                slave_up_hosts = get_slave_bricks_status(
                    slave_host, slave_vol)

                if current_slave_host not in slave_up_hosts:
                    if len(slave_up_hosts) > 0:
                        remote_host = "%s://%s@%s:%s" % (m.group(1),
                                                         m.group(2),
                                                         random.choice(
                                                             slave_up_hosts),
                                                         m.group(4))

            # Spawn the worker and agent in lock to avoid fd leak
            self.lock.acquire()

            self.status[w[0]['dir']].set_worker_status(self.ST_INIT)
            logging.info(lf('starting gsyncd worker',
                            brick=w[0]['dir'],
                            slave_node=remote_host))

            # Couple of pipe pairs for RPC communication b/w
            # worker and changelog agent.

            # read/write end for agent
            (ra, ww) = os.pipe()
            # read/write end for worker
            (rw, wa) = os.pipe()

            # spawn the agent process
            apid = os.fork()
            if apid == 0:
                os.close(rw)
                os.close(ww)
                os.execv(sys.executable, argv + ['--local-path', w[0]['dir'],
                                                 '--local-node', w[0]['host'],
                                                 '--local-node-id',
                                                 w[0]['uuid'],
                                                 '--agent',
                                                 '--rpc-fd',
                                                 ','.join([str(ra), str(wa),
                                                           str(rw), str(ww)])])
            pr, pw = os.pipe()
            cpid = os.fork()
            if cpid == 0:
                os.close(pr)
                os.close(ra)
                os.close(wa)
                args_to_worker = argv + ['--feedback-fd', str(pw),
                                         '--local-path', w[0]['dir'],
                                         '--local-node', w[0]['host'],
                                         '--local-node-id',
                                         w[0]['uuid'],
                                         '--local-id',
                                         '.' + escape(w[0]['dir']),
                                         '--rpc-fd',
                                         ','.join([str(rw), str(ww),
                                         str(ra), str(wa)]),
                                         '--subvol-num', str(w[2])]

                if w[3]:
                    args_to_worker.append('--is-hottier')
                args_to_worker += ['--resource-remote', remote_host]

                access_mount = boolify(gconf.access_mount)
                if access_mount:
                    os.execv(sys.executable, args_to_worker)
                else:
                    if unshare_propagation_supported():
                        logging.debug("Worker would mount volume privately")
                        unshare_cmd = ['unshare', '-m', '--propagation',
                                       'private']
                        cmd = unshare_cmd + args_to_worker
                        os.execvp("unshare", cmd)
                    else:
                        logging.debug("Mount is not private. It would be lazy"
                                      " umounted")
                        os.execv(sys.executable, args_to_worker)

            cpids.add(cpid)
            agents.add(apid)
            os.close(pw)

            # close all RPC pipes in monitor
            os.close(ra)
            os.close(wa)
            os.close(rw)
            os.close(ww)
            self.lock.release()

            t0 = time.time()
            so = select((pr,), (), (), conn_timeout)[0]
            os.close(pr)

            if so:
                ret = nwait(cpid, os.WNOHANG)
                ret_agent = nwait(apid, os.WNOHANG)

                if ret_agent is not None:
                    # Agent is died Kill Worker
                    logging.info(lf("Changelog Agent died, Aborting Worker",
                                    brick=w[0]['dir']))
                    errno_wrap(os.kill, [cpid, signal.SIGKILL], [ESRCH])
                    nwait(cpid)
                    nwait(apid)

                if ret is not None:
                    logging.info(lf("worker died before establishing "
                                    "connection",
                                    brick=w[0]['dir']))
                    nwait(apid)  # wait for agent
                else:
                    logging.debug("worker(%s) connected" % w[0]['dir'])
                    while time.time() < t0 + conn_timeout:
                        ret = nwait(cpid, os.WNOHANG)
                        ret_agent = nwait(apid, os.WNOHANG)

                        if ret is not None:
                            logging.info(lf("worker died in startup phase",
                                            brick=w[0]['dir']))
                            nwait(apid)  # wait for agent
                            break

                        if ret_agent is not None:
                            # Agent is died Kill Worker
                            logging.info(lf("Changelog Agent died, Aborting "
                                            "Worker",
                                            brick=w[0]['dir']))
                            errno_wrap(os.kill, [cpid, signal.SIGKILL], [ESRCH])
                            nwait(cpid)
                            nwait(apid)
                            break

                        time.sleep(1)
            else:
                logging.info(
                    lf("Worker not confirmed after wait, aborting it. "
                       "Gsyncd invocation on remote slave via SSH or "
                       "gluster master mount might have hung. Please "
                       "check the above logs for exact issue and check "
                       "master or slave volume for errors. Restarting "
                       "master/slave volume accordingly might help.",
                       brick=w[0]['dir'],
                       timeout=conn_timeout))
                errno_wrap(os.kill, [cpid, signal.SIGKILL], [ESRCH])
                nwait(apid)  # wait for agent
                ret = nwait(cpid)
            if ret is None:
                # If worker dies, agent terminates on EOF.
                # So lets wait for agent first.
                nwait(apid)
                ret = nwait(cpid)
            if exit_signalled(ret):
                ret = 0
            else:
                ret = exit_status(ret)
                if ret in (0, 1):
                    self.status[w[0]['dir']].set_worker_status(self.ST_FAULTY)
                    gf_event(EVENT_GEOREP_FAULTY,
                             master_volume=master.volume,
                             master_node=w[0]['host'],
                             master_node_id=w[0]['uuid'],
                             slave_host=slave_host,
                             slave_volume=slave_vol,
                             current_slave_host=current_slave_host,
                             brick_path=w[0]['dir'])
            time.sleep(10)
        self.status[w[0]['dir']].set_worker_status(self.ST_INCON)
        return ret

    def multiplex(self, wspx, suuid, slave_vol, slave_host, master):
        argv = sys.argv[:]
        for o in ('-N', '--no-daemon', '--monitor'):
            while o in argv:
                argv.remove(o)
        argv.extend(('-N', '-p', '', '--slave-id', suuid))
        argv.insert(0, os.path.basename(sys.executable))

        cpids = set()
        agents = set()
        ta = []
        for wx in wspx:
            def wmon(w):
                cpid, _ = self.monitor(w, argv, cpids, agents, slave_vol,
                                       slave_host, master)
                time.sleep(1)
                self.lock.acquire()
                for cpid in cpids:
                    errno_wrap(os.kill, [cpid, signal.SIGKILL], [ESRCH])
                for apid in agents:
                    errno_wrap(os.kill, [apid, signal.SIGKILL], [ESRCH])
                self.lock.release()
                finalize(exval=1)
            t = Thread(target=wmon, args=[wx])
            t.start()
            ta.append(t)

        # monitor status was being updated in each monitor thread. It
        # should not be done as it can cause deadlock for a worker start.
        # set_monitor_status uses flock to synchronize multple instances
        # updating the file. Since each monitor thread forks worker and
        # agent, these processes can hold the reference to fd of status
        # file causing deadlock to workers which starts later as flock
        # will not be release until all references to same fd is closed.
        # It will also cause fd leaks.

        self.lock.acquire()
        set_monitor_status(gconf.get("state-file"), self.ST_STARTED)
        self.lock.release()
        for t in ta:
            t.join()


def distribute(*resources):
    master, slave = resources
    mvol = Volinfo(master.volume, master.host)
    logging.debug('master bricks: ' + repr(mvol.bricks))
    prelude = []
    si = slave
    slave_host = None
    slave_vol = None

    if isinstance(slave, SSH):
        prelude = gconf.ssh_command.split() + [slave.remote_addr]
        si = slave.inner_rsc
        logging.debug('slave SSH gateway: ' + slave.remote_addr)
    if isinstance(si, FILE):
        sbricks = {'host': 'localhost', 'dir': si.path}
        suuid = uuid.uuid5(uuid.NAMESPACE_URL, slave.get_url(canonical=True))
    elif isinstance(si, GLUSTER):
        svol = Volinfo(si.volume, slave.remote_addr.split('@')[-1])
        sbricks = svol.bricks
        suuid = svol.uuid
        slave_host = slave.remote_addr.split('@')[-1]
        slave_vol = si.volume

        # save this xattr for the session delete command
        old_stime_xattr_name = getattr(gconf, "master.stime_xattr_name", None)
        new_stime_xattr_name = "trusted.glusterfs." + mvol.uuid + "." + \
            svol.uuid + ".stime"
        if not old_stime_xattr_name or \
           old_stime_xattr_name != new_stime_xattr_name:
            gconf.configinterface.set("master.stime_xattr_name",
                                      new_stime_xattr_name)
    else:
        raise GsyncdError("unknown slave type " + slave.url)
    logging.debug('slave bricks: ' + repr(sbricks))
    if isinstance(si, FILE):
        slaves = [slave.url]
    else:
        slavenodes = set(b['host'] for b in sbricks)
        if isinstance(slave, SSH) and not gconf.isolated_slave:
            rap = SSH.parse_ssh_address(slave)
            slaves = ['ssh://' + rap['user'] + '@' + h + ':' + si.url
                      for h in slavenodes]
        else:
            slavevols = [h + ':' + si.volume for h in slavenodes]
            if isinstance(slave, SSH):
                slaves = ['ssh://' + rap.remote_addr + ':' + v
                          for v in slavevols]
            else:
                slaves = slavevols

    workerspex = []
    for idx, brick in enumerate(mvol.bricks):
        if is_host_local(brick['uuid']):
            is_hot = mvol.is_hot(":".join([brick['host'], brick['dir']]))
            workerspex.append((brick,
                               slaves[idx % len(slaves)],
                               get_subvol_num(idx, mvol, is_hot),
                               is_hot))
    logging.debug('worker specs: ' + repr(workerspex))
    return workerspex, suuid, slave_vol, slave_host, master


def monitor(*resources):
    # Check if gsyncd restarted in pause state. If
    # yes, send SIGSTOP to negative of monitor pid
    # to go back to pause state.
    if gconf.pause_on_start:
        errno_wrap(os.kill, [-os.getpid(), signal.SIGSTOP], [ESRCH])

    """oh yeah, actually Monitor is used as singleton, too"""
    return Monitor().multiplex(*distribute(*resources))
