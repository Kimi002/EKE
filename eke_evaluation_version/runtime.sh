#!/bin/bash

TIMEFORMAT='%R seconds.'


{ time python3 client.py negotiate --user=dummy_user --passwd=dummy_pwd; } 2>>runtime_2048.txt