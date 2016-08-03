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
  you run the following, the benchmark is run on a 3 client setup.
```
python scripts/emulab.py nameofnode-0.apt.emulab.net
```
* You could optionally specify less number of clients with `--clients=` argument
* The emulab script performs the following actions:
    * Sends code from the current dir to all nodes.
    * Checks if hugepages are enabled for all nodes.
    * If not, modifies grub.conf to enable hugepages. In this case, the machines will need a restart and the script will exit.
    * Disable memory pinning limits and mounts a filesystem with 1GB hugepages.
    * Compiles the code
    * Start the server and client processes.
    ```
    Note: client and server processes are reversed from the conventional sense because the client process is the one actually doing most of the work.
    ``` 
    * Collects the log files from the run and rsyncs them back to the directory

## Steps for running the benchmarks


