#!/usr/bin/env python

import os
import xml.etree.ElementTree as ET
import sys
import subprocess
import time
import datetime
import logging
import argparse
import pprint

logger=logging.getLogger("BenchmarkRunner")


def ssh(server, cmd, checked=True):
    if checked:
        return subprocess.check_call('ssh %s "%s"' % (server, cmd),
                                     shell=True, stdout=sys.stdout)
    else:
        return subprocess.call('ssh %s "%s"' % (server, cmd),
                               shell=True, stdout=sys.stdout)

class BenchmarkRunner(object):

    def __init__(self, server, extra_args, num_clients=None, user=None):
        self.user = user
        self.num_clients = num_clients
        self.extra_server_args = '--hugePages'
        self.extra_client_args = extra_args + ' --hugePages'
        self.node_type = None
        self.server = server
        self.node_names = []
        self.host_names = []
        self.start_time = None
        self.end_time = None

    def __enter__(self):
        self.populate_hosts()
        if self.num_clients is not None:
            if self.num_clients >= len(self.node_names):
                logger.error("Not enough machines, use less number of clients")
                sys.exit(1)
            self.node_names = self.node_names[:self.num_clients + 1]
            self.host_names = self.host_names[:self.num_clients + 1]
        self.start_time = datetime.datetime.now()
        return self 

    def __exit__(self, type, value, traceback):
       self.killall()

    def populate_hosts(self):
        out = subprocess.check_output("ssh %s /usr/bin/geni-get manifest" % self.server,
                                      shell=True)
        logger.debug("Manifest output %s", pprint.pformat(out))
        root = ET.fromstring(out)
        for child in root.getchildren():
          if child.tag.endswith('node'):
            for host in child.getchildren():
              if host.tag.endswith('host'):
                if self.user:
                    self.host_names.append(self.user + '@' + host.get('name'))
                else:
                    self.host_names.append(host.get('name'))
                self.node_names.append('node-%d' % len(self.node_names))
              if self.node_type is None and host.tag.endswith('hardware_type'):
                self.node_type = host.get('name')

    def get_name(self):
        return (self.start_time.strftime('%Y%m%d%H%M%S') +
                '-%d-clients-%s' % (len(self.node_names) - 1, self.node_type))

    def collect_results(self):
        assert(self.end_time != None)

        log_dir = os.path.join('logs', self.get_name())
        latest = os.path.join('logs', 'latest')
        try:
            os.makedirs(log_dir)
        except:
            pass
        try:
            os.unlink(latest)
        except:
            pass
        try:
            os.symlink(self.get_name(), latest)
        except:
            pass

        legend_file_name = os.path.join(log_dir, "legend-%s.log" % self.get_name())
        with open(legend_file_name, 'w') as f:
            print >> f, 'Commit: %s' % subprocess.check_output('git log -1 --oneline', shell=True)
            print >> f, 'Run on: %s' % ' '.join(self.with_fqdn(self.host_names))
            print >> f, self.end_time.strftime('Experiment completed at %d/%m/%y %H:%M:%S')
            print >> f, 'Experiment run time: %s' % str(self.end_time - self.start_time)
        subprocess.call("rsync -ave ssh %s:~/ibv-bench/%s*.log %s/" %
                (self.host_names[0], self.get_name(), log_dir),
                shell=True, stdout=sys.stdout)

        try:
            out = os.path.join('logs', 'latest', 'out')
            os.symlink('%s-out.log' % self.get_name(), out)
            err = os.path.join('logs', 'latest', 'err')
            os.symlink('%s-err.log' % self.get_name(), err)
        except:
            pass

    def with_fqdn(self, hosts):
        return ['%s.apt.emulab.net' % h for h in hosts]

    def send_code(self, server):
        logger.info("Sending code to %s", server)
        subprocess.check_call("rsync -ave ssh --exclude 'logs/*' " +
                              "./ %s:~/ibv-bench/ > /dev/null" % server,
                              shell=True, stdout=sys.stdout)

    def compile_code(self, server):
        logger.info("Compiling code on %s", server)
        ssh(server, '(cd ibv-bench; (make clean; make -j 8) &> ~/ibv-bench/build.log)')

    def start_servers(self):
        procs = []
        for host, node in zip(self.host_names[1:], self.node_names[1:]):
            cmd = ('(cd ibv-bench; ./ibv-bench server %s %s > server_%s.log 2>&1)' %
                        (node, self.extra_server_args, node))
            logger.debug("Starting server with cmd:%s", cmd)
            procs.append(subprocess.Popen(['ssh', host, cmd]))
        return procs

    def killall(self):
        for host in self.host_names:
            logger.debug("Killing processes on %s",host)
            ssh(host, 'pkill -9 ibv-bench', checked=False)

    def update_limits(self, server):
        logger.debug("Updating pinning limits")
        ssh(server, 'sudo ~/ibv-bench/scripts/disable-pin-limits')

    def check_huge_pages(self, server):
        r = ssh(server, '~/ibv-bench/scripts/check-hugepages', checked=False)
        if r:
            logger.info("Hugepages are not configured on %s", server)
        return r == 0

    def enable_huge_pages(self, server):
        """Notice: this modifies grub.conf to update bootparams and then
        reboots the machine, so this script needs to be restarted if
        this is used.
        """
        logger.info("Enabling hugepages on %s, Machine will reboot", server)
        ssh(server, 'sudo ~/ibv-bench/scripts/enable-hugepages')
        ssh(server, 'sudo reboot')

    def mount_huge_pages(self, server):
        logger.debug("Mounting hugetlbfs on %s", server)
        ssh(server, 'sudo ~/ibv-bench/scripts/mount-hugepages')

    def run(self):
        try:
            for host in self.host_names:
                self.send_code(host)

            some_rebooting = False
            for host in self.host_names:
                r = self.check_huge_pages(host)
                if not r:
                    self.enable_huge_pages(host)
                    some_rebooting = True
            if some_rebooting:
                logger.warning("Some machines rebooting to enable hugepages; " +
                               "restart this script when all machines are " +
                               "back online")
                raise SystemExit()

            for host in self.host_names:
                self.update_limits(host)
                self.mount_huge_pages(host)

            for host in self.host_names:
                self.compile_code(host)

            procs = self.start_servers()

            time.sleep(5)

            logger.info("Starting client processes; " +
                        "benchmarks will take a few hours.")
            ssh(self.host_names[0],
                '(cd ibv-bench; ' +
                './ibv-bench client %s %s 2>&1 > %s-out.log | tee %s-err.log)'
                    % (' '.join(self.node_names[1:]),
                       self.extra_client_args,
                       self.get_name(),
                       self.get_name()))
        finally:
            self.end_time = datetime.datetime.now()
            logger.info("Collecting results ...")
            self.collect_results()
            logger.info("Results collected")

def main():
    if not os.path.exists(os.path.join('scripts', 'emulab.py')):
        raise Exception('Run this directly from top-level of the project.')
    parser = argparse.ArgumentParser(description="\n Runner script to run " +
                                                 "the benchmark on Apt testbed")
    requiredNamed = parser.add_argument_group('Required argument(s)')
    requiredNamed.add_argument("hostname", nargs=1,
                               help=" hostname of node-0 in the format " +
                                    "apt**.apt.emulab.net")
    optionals = parser.add_argument_group('Optional arguments')
    optionals.add_argument("--clients", type=int, default=None,
                           help="Number of clients. Should be <= n-1 for an " +
                                "experiment with n nodes.")
    optionals.add_argument("--log-level", default="INFO",
                            help="python logging level")
    optionals.add_argument("--cmd", default="run",
                           help="Method to execute. Defaults to run")
    optionals.add_argument("--user", default=None,
                           help="Cloudlab username if different from the " +
                                "current user")
    args, unknowns = parser.parse_known_args()

    subprocess.check_call('git submodule init', shell=True, stdout=sys.stdout)
    subprocess.check_call('git submodule update', shell=True, stdout=sys.stdout)
    if not args.user:
        server = args.hostname[0]
    else:
        server = args.user+"@"+args.hostname[0]
    num_clients = args.clients
    extra_args = " ".join(unknowns)
    loglevel=getattr(logging, args.log_level.upper(), "INFO")
    logging.basicConfig(level=loglevel)
    
    with BenchmarkRunner(server, extra_args, num_clients=num_clients, user=args.user) as br:
        logger.info('Found hosts %s' % ' '.join(br.host_names))
        cmd = args.cmd
        if cmd == 'run':
            br.run()

if __name__ == '__main__': main()
