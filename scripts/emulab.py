#!/usr/bin/env python

import os
import xml.etree.ElementTree as ET
import sys
import subprocess
import time
import datetime

class BenchmarkRunner(object):

    def __init__(self, server):
        self.node_type = None
        self.server = server
        self.node_names = []
        self.host_names = []
        self.start_time = None
        self.end_time = None
        self.experiment_name = None
        self.legend = None
        self.completed_message = None


    def ssh(self, cmd, checked=True):
        if checked:
            return subprocess.check_call('ssh %s "%s"' % (self.server, cmd),
                                         shell=True, stdout=sys.stdout)
        else:
            return subprocess.call('ssh %s "%s"' % (self.server, cmd),
                                   shell=True, stdout=sys.stdout)

    def configure(self):
        self.populate_hosts()
        self.generate_experiment_name()

    def populate_hosts(self):
        out = subprocess.check_output("ssh %s /usr/bin/geni-get manifest" % self.server,
                                      shell=True)

        root = ET.fromstring(out)
        for child in root.getchildren():
          if child.tag.endswith('node'):
            for host in child.getchildren():
              if host.tag.endswith('host'):
                self.host_names.append(host.get('name'))
                self.node_names.append('node-%d' % len(self.node_names))
              if self.node_type is None and host.tag.endswith('hardware_type'):
                self.node_type = host.get('name')
              
    def generate_experiment_name(self):
        self.start_time = datetime.datetime.now()
        self.experiment_name = str(len(self.node_names[1:])) + "_" + \
                               self.node_type + "_clients_" + \
                               self.start_time.strftime('%d_%m_%y_%H_%M_%S')

    def generate_legend(self):
        commit_mesg = "Commit: " + \
                       subprocess.check_output('git log -1 --pretty=format:"%h%x09%an%x09%ad%x09%s"',
                                                shell=True)
        logger_mesg = "Logged by: " + self.node_names[0] + \
                                     "(" + self.host_names[0] + ")"
        duration_mesg = "Duration: " + str(self.end_time - self.start_time)
        self.legend = "\n".join([commit_mesg, logger_mesg, 
                                self.completed_message, duration_mesg])

    def generate_completion_message(self):
        self.end_time = datetime.datetime.now()
        self.completed_message = self.end_time.strftime("Experiment completed" + \
                                 " and returned on %d/%m/%y %H:%M:%S")

    def collect_artifacts(self):
        log_dir = os.path.join(os.path.dirname(__file__),self.experiment_name)
        subprocess.check_output("mkdir -p %s" % log_dir, shell=True)
        legend_file_name = os.path.join(log_dir, "legend_%s.log" % self.experiment_name)
        with open(legend_file_name) as f:
            f.write(self.legend)
        subprocess.check_output("rsync -ave ssh %s:~/ibv-bench/*.log %s/" % (self.host_names[0], log_dir),
                                shell=True, stdout=sys.stdout)


    def with_fqdn(self, hosts):
        return ['%s.apt.emulab.net' % h for h in hosts]

    def send_code(self, server):
        subprocess.check_call("rsync -ave ssh ./ %s:~/ibv-bench/" % server,
                              shell=True, stdout=sys.stdout)

    def compile_code(self, server):
        ssh(server, '(cd ibv-bench; make clean; make -j 8 &> ~/ibv-bench/build.log)')

    def start_servers(self):
        procs = []
        for host, node in zip(self.host_names, self.node_names):
            procs.append(subprocess.Popen(['ssh', host,
                              '(cd ibv-bench; ./ibv-bench server %s &> server_%s.log)' % (node,node)]))
        return procs

    def killall(self):
        for host in self.host_names:
            ssh(host, 'pkill -9 ibv-bench', checked=False)

    def start(self):
        for host in self.host_names:
            print 'Sending code to %s' % host
            self.send_code(host)

        for host in self.host_names:
            print 'Compiling code on %s' % host
            self.compile_code(host)

        procs = self.start_servers()

        time.sleep(5)

        print 'Starting the client'
        ssh(self.host_names[0],
            '(cd ibv-bench; ./ibv-bench client %s --hugePages > %s_out.log 2> %s_err.log)' % (' '.join(nodes[1:]),
                                               self.experiment_name,
                                               self.experiment_name))
        self.generate_completion_message()

        print 'All done; tearing down'
        self.killall()

def main():
    if not os.path.exists(os.path.join('scripts', 'emulab.py')):
        raise Exception('Run this directly from top-level of the project.')

    if len(sys.argv) < 2:
        raise Exception('Need Emulab server address.')

    server = sys.argv[1]
    br = BenchmarkRunner(server)
    br.configure()
    print 'Found hosts %s' % ' '.join(br.host_names)
    cmd = 'start'
    if len(sys.argv) == 3:
        cmd = sys.argv[2]

    if cmd == 'killall':
        br.killall()
    elif cmd == 'start':
        br.start()

if __name__ == '__main__': main()
