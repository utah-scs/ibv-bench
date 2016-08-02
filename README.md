# ibv-bench

Microbenchmarks for evaluating infiniband verbs performance on [Apt](http://docs.aptlab.net/).

# Guidelines for running the benchmarks
* You'll need an account to use testbeds such as Cloudlab, Apt and Emulab. Follow this [link](http://docs.cloudlab.us/getting-started.html) for detailed instructions.
* The benchmarks need to be run on Apt site. Find the hardware specifications [here](http://docs.aptlab.net/hardware.html).
* You can either use the [infiniband_dev](https://www.cloudlab.us/p/utahstud/infiniband_dev) profile or create your own. If you are using infiniband_dev, you'll find details on how the hardware is configured in the instructions before initialisation.
* Use [emulab.py](scripts/emulab.py) for straight forward execution and collection of results.

