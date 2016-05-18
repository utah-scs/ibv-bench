#!/usr/bin/env python

import os
import xml.etree.ElementTree as ET
import sys
import subprocess
import time

def ssh(server, cmd, checked=True):
    if checked:
        return subprocess.check_call('ssh %s "%s"' % (server, cmd),
                                     shell=True, stdout=sys.stdout)
    else:
        return subprocess.call('ssh %s "%s"' % (server, cmd),
                               shell=True, stdout=sys.stdout)

def get_hosts(server):
    out = subprocess.check_output("ssh %s /usr/bin/geni-get manifest" % server,
                                  shell=True)

    root = ET.fromstring(out)

    node_names = []
    host_names = []
    for child in root.getchildren():
      if child.tag.endswith('node'):
        for host in child.getchildren():
          if host.tag.endswith('host'):
            host_names.append(host.get('name'))
            node_names.append('node-%d' % len(node_names))

    return (node_names, host_names)

def with_fqdn(hosts):
    return ['%s.apt.emulab.net' % h for h in hosts]

def send_code(server):
    subprocess.check_call("rsync -ave ssh ./ %s:~/ibv-bench/" % server,
                          shell=True, stdout=sys.stdout)

def compile_code(server):
    ssh(server, '(cd ibv-bench; make clean; make -j 8)')

def start_servers(hosts, nodes):
    procs = []
    for host, node in zip(hosts, nodes):
        procs.append(subprocess.Popen(['ssh', host,
                          '(cd ibv-bench; ./ibv-bench server %s)' % node]))
    return procs

def killall(hosts):
    for host in hosts:
        ssh(host, 'pkill -9 ibv-bench', checked=False)

def start(hosts, nodes):
    for host in hosts:
        print 'Sending code to %s' % host
        send_code(host)

    for host in hosts:
        print 'Compiling code on %s' % host
        compile_code(host)

    procs = start_servers(hosts[1:], nodes[1:])

    time.sleep(5)

    print 'Starting the client'
    ssh(hosts[0],
        '(cd ibv-bench; ./ibv-bench client %s --hugePages)' % ' '.join(nodes[1:]))

    print 'All done; tearing down'
    killall(hosts)

def main():
    if not os.path.exists(os.path.join('scripts', 'emulab.py')):
        raise Exception('Run this directly from top-level of the project.')

    if len(sys.argv) < 2:
        raise Exception('Need Emulab server address.')

    server = sys.argv[1]

    nodes, hosts = get_hosts(server)
    print 'Found hosts %s' % ' '.join(hosts)

    cmd = 'start'
    if len(sys.argv) == 3:
        cmd = sys.argv[2]

    if cmd == 'killall':
        killall(hosts)
    elif cmd == 'start':
        start(hosts, nodes)

if __name__ == '__main__': main()
