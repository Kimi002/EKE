#!/bin/bash

TIMEFORMAT='%R'

for n in {1..10};
do
time=$( { time python3 client.py exchange --passwd=time; } 2>&1 )
# timeVAL=$(echo "$time" | grep real | awk '{print $2}')
timeVAL=$(echo "$time" | tail -n 1)
echo "$n,$timeVAL" >> runtime_2048.csv
done