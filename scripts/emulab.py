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

def pdsh(cmd, checked=True):
    """ Runs command on remote hosts using pdsh on remote hosts"""
    logger.info("Running parallely on all hosts,%s " % cmd)
    if checked:
        return subprocess.check_call('pdsh -w^./.emulab-hosts "%s"' % cmd,
                                     shell=True, stdout=sys.stdout)
    else:
        return subprocess.call('pdsh -w^./.emulab-hosts "%s"' %cmd,
                               shell=True, stdout=sys.stdout)


class BenchmarkRunner(object):

    def __init__(self, server, extra_args, user=None, profile=None, binary="ibv-bench", num_clients=None):
        self.num_clients = num_clients
        self.extra_server_args = '--hugePages'
        self.extra_client_args = extra_args + ' --hugePages'
        self.node_type = None
        self.server = server
        self.node_names = []
        self.host_names = []
        self.public_names = []
        self.start_time = None
        self.end_time = None
        self.parallel = self.cmd_exists("pdsh")
        if not self.parallel:
            logger.warn("Remote commands could be faster if you install and configure pdsh")
        self.user = user if user else ""
        self.profile = False if profile is None else True 
        self.binary = binary

    def __enter__(self):
        self.populate_hosts()
        if self.num_clients is not None:
            if self.num_clients >= len(self.node_names):
                logger.error("Not enough machines, use less number of clients")
                sys.exit(1)
            self.node_names = self.node_names[:self.num_clients + 1]
            self.host_names = self.host_names[:self.num_clients + 1]
        self.start_time = datetime.datetime.now()
	if self.parallel:
            with open("./.emulab-hosts",'w') as f:
                    for host in self.host_names:
                        f.write(host[0]+'\n')

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
                self.host_names.append(self.user + host.get('name'))
                self.node_names.append('node-%d' % len(self.node_names))
              if host.tag.endswith('vnode'):
                self.public_names.append(host.get('name') + ".apt.emulab.net")
              if self.node_type is None and host.tag.endswith('hardware_type'):
                self.node_type = host.get('name')
        
    def get_name(self):

        size=self.extra_client_args.split("minChunkSize=",4)[1].split(" ")[0]
        chunks=self.extra_client_args.split("minChunksPerMessage=",4)[1].split(" ")[0]
        return (self.start_time.strftime('%Y%m%d%H%M') +
                '-%d-clients-%sB-%schunks-%s' % (len(self.node_names) - 1, size, chunks, self.node_type))

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

    def compile_code(self, server, parallel=False):
        if parallel:
            logger.info("Compiling code parallely")
            pdsh('(cd ibv-bench; (make clean; make all -j 8) &> ~/ibv-bench/build.log)')
        else:
            logger.info("Compiling code on %s", server)
            ssh(server, '(cd ibv-bench; (make clean; make all -j 8) &> ~/ibv-bench/build.log)')

    def start_servers(self):
        procs = []
        for host, node in zip(self.host_names[1:], self.public_names[1:]):
            cmd = ('(cd ibv-bench; ./%s server %s %s > server_%s.log 2>&1)' %
                        (self.binary, node, self.extra_server_args, node))
            logger.debug("Starting server with cmd:%s", cmd)
            procs.append(subprocess.Popen(['ssh', host, cmd]))
        return procs

    def killall(self):
        for host in self.host_names:
            logger.debug("Killing processes on %s",host)
            ssh(host, 'pkill -9 %s' % self.binary, checked=False)

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
            if self.parallel:
                self.compile_code(self.host_names[0],self.parallel)
            else:
                for host in self.host_names:
                    self.compile_code(host,self.parallel)

            procs = self.start_servers()
	    time.sleep(5)
	    if self.profile:
	        logger.info("running with profiler")
		ssh(self.host_names[0], 'sudo su -c \'echo -1 > /proc/sys/kernel/perf_event_paranoid\'')
	        client_cmd = ('(cd ibv-bench; python pmu-tools/ucevent/ucevent.py' +
                		' -I 100 --socket 0 -o %s-membw.csv -x, --scale MB' % self.get_name() +
                		' iMC.MEM_BW_TOTAL CBO.LLC_DDIO_MEM_TOTAL_BYTES CBO.LLC_PCIE_MEM_TOTAL_BYTES  -- sh -c \'./%s' % self.binary +
				' client %s %s 2>&1 > %s-out.log | tee %s-err.log\')'
				% (' '.join(self.public_names[1:]),
                		self.extra_client_args,
               			self.get_name(),
                		self.get_name()))
	    else:
		logger.info("Running without profiler")
		client_cmd = ('(cd ibv-bench; ' +
                                './%s client %s %s 2>&1 > %s-out.log | tee %s-err.log)'
                                % (self.binary, ' '.join(self.public_names[1:]),
                                self.extra_client_args,
                                self.get_name(),
                                self.get_name()))

            logger.info("Starting client processes; " +
                        "benchmarks will take a few hours.")
            ssh(self.host_names[0], client_cmd)

        finally:
            self.end_time = datetime.datetime.now()
            logger.info("Collecting results ...")
            self.collect_results()
            logger.info("Results collected")

    def cmd_exists(self, cmd):
        return subprocess.call("type " + cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0


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
    optionals.add_argument("--profile", default=None,
			   help="Profile memory bandwidth using pmu-tools")
    optionals.add_argument("--nosend", default=False,
			   help="Don't send data")
    optionals.add_argument("--chunks", default="all",
			   help="Number of objects to send")
    optionals.add_argument("--size", default="both",
			   help="Object size")
    optionals.add_argument("--seconds", default="30",
			   help="Time to run each data point")

    args, unknowns = parser.parse_known_args()

    subprocess.check_call('git submodule init', shell=True, stdout=sys.stdout)
    subprocess.check_call('git submodule update', shell=True, stdout=sys.stdout)
    if not args.user:
        server = args.hostname[0]
    else:
        server = args.user+"@"+args.hostname[0]
    if not args.nosend:
	binary = "ibv-bench"
    else:
	binary = "nosend"
    num_clients = args.clients
    #extra_args = " ".join(unknowns)
    loglevel=getattr(logging, args.log_level.upper(), "INFO")
    logging.basicConfig(level=loglevel)
    extra_args = []
    if args.chunks == "all":
        for i in range(1,32):
            if args.size == "both":
                extra_args.append(("--minChunkSize=128 --maxChunkSize=128 " 
                                 "--minChunksPerMessage=%s --maxChunksPerMessage=%s " % (str(i),str(i)) +
                                 "--seconds=%s" % args.seconds))
                extra_args.append(("--minChunkSize=1024 --maxChunkSize=1024 " 
                                 "--minChunksPerMessage=%s --maxChunksPerMessage=%s " %(str(i),str(i)) +
                                 "--seconds=%s" % args.seconds))
            else:
                extra_args.append(("--minChunkSize=%s --maxChunkSize=%s " %(args.size, args.size) + 
                                 "--minChunksPerMessage=%s --maxChunksPerMessage=%s " %(str(i), str(i)) +
                                 "--seconds=%s" % args.seconds))
    else:
        if args.size == "both":
            extra_args.append(("--minChunkSize=128 --maxChunkSize=128 " 
                             "--minChunksPerMessage=%s --maxChunksPerMessage=%s " %(args.chunks,args.chunks) +
                             "--seconds=%s" % args.seconds))
            extra_args.append(("--minChunkSize=1024 --maxChunkSize=1024 " 
                             "--minChunksPerMessage=%s --maxChunksPerMessage=%s " %(args.chunks, args.chunks) +
                             "--seconds=%s" % args.seconds))
        else:
            extra_args.append(("--minChunkSize=%s --maxChunkSize=%s " %(args.size, args.size) +
                             "--minChunksPerMessage=%s --maxChunksPerMessage=%s " %(args.chunks, args.chunks) +
                             "--seconds=%s" % args.seconds))


    
    for extra_arg in extra_args:
        logger.info("Running with %s" % extra_arg)
        with BenchmarkRunner(server, extra_arg, args.user, args.profile, binary, num_clients=num_clients) as br:
            logger.info('Found hosts %s' % ' '.join(br.host_names))
            cmd = args.cmd
            if cmd == 'run':
                br.run()

if __name__ == '__main__': main()
