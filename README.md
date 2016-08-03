# ibv-bench

Microbenchmarks for evaluating infiniband verbs performance on [Apt](http://docs.aptlab.net/).

## Guidelines for running the benchmarks
* You'll need an account to use testbeds such as Cloudlab, Apt and Emulab. Follow this [link](http://docs.cloudlab.us/getting-started.html) for detailed instructions.
* The benchmarks need to be run on Apt site. Find the hardware specifications [here](http://docs.aptlab.net/hardware.html).
* You can either use the [infiniband_dev](https://www.cloudlab.us/p/utahstud/infiniband_dev) profile or create your own. If you are using infiniband_dev, you'll find details on how the hardware is configured in the instructions before initialisation.
* Use [emulab.py](scripts/emulab.py) for straight forward execution and collection of results.
* For instance, if you initialised infiniband_dev profile with 4 nodes. When you run the following, the benchmark is run on a 3 client setup.
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
