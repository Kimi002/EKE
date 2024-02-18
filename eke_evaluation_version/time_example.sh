#!/bin/bash

# 2 ways to measure time
# TIMEFORMAT time measures in seconds
# start-end measures in nanoseconds

TIMEFORMAT='It took %R seconds.'

start=$(date +%s%N)

time {
    sleep 2
}
end=$(date +%s%N)

echo "Elapsed time: $(($end-$start)) ns"