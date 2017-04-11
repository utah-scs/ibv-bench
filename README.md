# ibv-bench

Microbenchmarks for evaluating performance characteristics of large transfers over infiniband on the  [Apt](http://docs.aptlab.net/) cluster.

## Guidelines for running the benchmarks

* Since these experiments require a particular hardware and software setup to
  run, the recommended way of running them (and the way described in this
  README) is to use the CloudLab testbed, which will give you access to the
  [r320](http://docs.aptlab.net/hardware.html#%28part._apt-cluster%29) nodes used in
  our evaluation.
* You'll need an account to use the testbed. If you already have an account on
  cloudlab.us or emulab.net, you can simply use that account. If you don't ahve
  one, follow this [link](http://docs.cloudlab.us/getting-started.html) for
  detailed instructions. Accounts are open (and free) to all academic
  researchers.
* You will use a "profile", which is a pre-configured hardware description and
  a disk image. We recommend using the
  [aniraj_thesis_ddio](https://www.cloudlab.us/instantiate.php?project=RAMCloud&profile=aniraj_thesis_ddio#) profile.
* If you instantiate `n` nodes, the script will run on an `n-1` client setup. We recommend instantiating a 16 node 
  cluster since all client threads could be pinned to hardware threads in such a setup on r320 nodes.
* Clone the repository and run `run-all.sh` on node-0 to run all possible data points.
* Edit `run-all.sh` to limit runs and save time.

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

## Steps for running the benchmark while profiling Memory, DDIO and PCIe traffic

1. We use [pmu-tools](https://github.com/andikleen/pmu-tools) repository 
   courtesy of [Andi Kleen](https://github.com/andikleen) to measure uncore events via perf.
2. It's always best to run single data points (fixed chunk size, number of chunks and mode of copy)
   for one of the available profiles to measure DDIO Bandwidth, Memory Bandwidth and PCIE bandwidth
3. Running independent experiments over all chunks for 128B and 1024B objects and the delta experiments takes around 15 hours.
4. You can run the following in bash (on node-0/client-0 in the experiment) to run all data points. To repeat results from 
   Aniraj's thesis, run on r320 nodes on APT with 15 clients:
   ```
   bash run-all.sh
   ```
