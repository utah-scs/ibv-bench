# ibv-bench

Microbenchmarks for evaluating infiniband verbs performance on the  [Apt](http://docs.aptlab.net/) cluster.

## Guidelines for running the benchmarks

* Since these experiments require a particular hardware and software setup to
  run, the recommended way of running them (and the way described in this
  README) is to use the CloudLab testbed, which will give you access to the
  [apt cluster](http://docs.aptlab.net/hardware.html).
* You'll need an account to use the testbed. If you already have an annount on
  cloudlab.us or emulab.net, you can simply use that account. If you don't ahve
  one, follow this [link](http://docs.cloudlab.us/getting-started.html) for
  detailed instructions. Accounts are open (and free) to all academic
  researchers.
* You will use a "profile", which is a pre-configured hardware description and
  set of disk images. We recommend using the
  [infiniband_dev](https://www.cloudlab.us/p/utahstud/infiniband_dev) profile
  that we have built.
* Use [emulab.py](scripts/emulab.py) for straight forward execution and
  collection of results.
* For instance, if you initialised infiniband_dev profile with 4 nodes. When
  you run the following from your local machine, the benchmark is run on a 3 client setup.
```
python scripts/emulab.py nameofnode-0.apt.emulab.net
```
* The emulab script performs the following actions:
    * Sends code from the current dir to all nodes.
    * Checks if hugepages are enabled for all nodes.
    * If not, modifies grub.conf to enable hugepages. In this case, the machines will need a restart and the script will exit.
    * Disable memory pinning limits and mounts a filesystem with 1GB hugepages.
    * Compiles the code
    * Start the server and client processes.
    ```
    Note: client and server processes are reversed from the conventional sense 
    "client" process is the one actually doing most of the work.
    ```
    * Collects the log files from the run and rsyncs them back to the directory

## Steps for running the benchmarks

1. Clone this repository somewhere on your local machine.
2. Create a new "experiment" on CloudLab's Apt cluster by following this link:
  https://www.cloudlab.us/p/utahstud/infiniband_dev
  * If you don't have an account on CloudLab or Emulab,
    [see here](http://docs.cloudlab.us/getting-started.html)
  * We recommend taking the defaults for the questions you are asked about the
    machine type to use and the size of the experiment
3. When the experiment has been created, take note of the hostname of the
   machines allocated to the node `node-0` in the experiment. Do this by
   looking at the "List View" tab of the experiment status page, and
   finding the entry for `node-0`. The hostname will be something like
   `aptXXX.apt.emulab.net`
  * Make sure that you can `ssh` into this node without a password; when you
     created your CloudLab account, it asked you to upload an ssh public key.
     Make sure that you have access to this key(private) (for example, in your `.ssh/identity` file,
     loaded into an `ssh-agent`, etc.), and make sure that you are using your
     CloudLab username as the username you're passing to `ssh`.
4. On your local machine, run the following command from your clone of this
   repository:
   ```
   python scripts/emulab.py aptXXX.apt.emulab.net
   ```
   ... replacing `aptXXX` with the hostname you noted above in step 3.
  * You will probably be asked by `ssh` to say "yes" to the host keys for the
     machines in your experiment
  * You may get a message like:
     ```
     Some machines rebooting to enable hugepages; restart this script when all machines are back online
     ```
     This will take about 5-10 minutes. You can simply ping the hosts listed
     above and wait for them to come back up.
  * For the full list of options, you might run:
    ```
    python scripts/emulab.py -h
    ```
5. Wait a few hours for the benchmarks to all run!
  * The `emulab.py` script runs a large number of experiments across
     a large number of parameters, so it takes several hours to
     finish
  * When it finishes, it will copy all results to the `logs/` subdirectory of
    the repository on your local machine

## Steps for running the benchmark while profiling Memory, DDIO and PCIe traffic

1. We use [pmu-tools](https://github.com/andikleen/pmu-tools) repository 
   courtesy of [Andi Kleen](https://github.com/andikleen) to measure uncore events via perf.
2. It's always best to run single data points (fixed chunk size, number of chunks and mode of copy)
   for one of the available profiles to measure DDIO Bandwidth, Memory Bandwidth and PCIE bandwidth
3. Running independent experiments over all chunks for 128B and 1024B objects and the delta experiments takes around 15 hours.
4. You can run the following in bash (on node-0/client-0 in the experiment) to run all data points. To repeat results from 
   Aniraj's thesis, run on r320 nodes on APT with 15 clients:
   ```
   for c in {1..32}
   do
     for s in {128,1024}
     do
       for m in {ddiobw,pciebw,membw}
       do 
         python scripts/emulab.py `hostname` --profile=$m --nocopyout true --seconds=60 --chunks=$c --size=$s > /dev/null 2>&1
         ps axf | grep python | grep ucevent |grep -v bash|grep -v ssh| awk '{print "kill -2 " $1}'|sh
         ps axf | grep python | grep ucevent |grep -v bash|awk '{print "kill -2 " $1}'|sh
         python scripts/emulab.py `hostname` --profile=$m --nozerocopy true --seconds=60 --chunks=$c --size=$s > /dev/null 2>&1
         ps axf | grep python | grep ucevent |grep -v bash|grep -v ssh| awk '{print "kill -2 " $1}'|sh
         ps axf | grep python | grep ucevent |grep -v bash|awk '{print "kill -2 " $1}'|sh
         python scripts/emulab.py `hostname` --profile=$m --onlydeltas true --seconds=60 --chunks=$c --size=$s > /dev/null 2>&1
         ps axf | grep python | grep ucevent |grep -v bash|grep -v ssh| awk '{print "kill -2 " $1}'|sh
         ps axf | grep python | grep ucevent |grep -v bash|awk '{print "kill -2 " $1}'|sh
       done
     done
   done
   ```
