```
make
```

On server (with hostname hostname-ib):

```
$ ./ibv-bench server hostname-ib --hugePages
```

On a separte client machine (connecting to hostname-ib):

```
$ ./ibv-bench client hostname-ib --hugePages
...
Took 8619 cycles per req
Rate: 26.554651 MB/s
```
