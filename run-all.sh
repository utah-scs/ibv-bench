#!/bin/bash
# replace the for loops to limit runs.
for size in {128,1024}
  do
  for profile in {membw,ddiobw,pciebw}
    do
    for chunks in {1..32}
      do
      for filter in {--nocopyout,--nozerocopy}
        do 
        #python scripts/emulab.py `hostname` --profile=$profile $filter true --seconds=90 --chunks=$chunks --size=$size --profileinterval 100 > run-$profile-$filter-$chunks-$size.log 2>&1
        python scripts/emulab.py `hostname` --profile=$profile $filter true --seconds=90 --chunks=$chunks --size=$size --profileinterval 100
        ps axf | grep python | grep ucevent |grep -v bash|grep -v ssh| awk '{print "kill -2 " $1}'|sh
        ps axf | grep python | grep ucevent |grep -v bash|awk '{print "kill -2 " $1}'|sh
      done
    done
  done
done
