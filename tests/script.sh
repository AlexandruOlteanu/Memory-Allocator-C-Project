#!/bin/bash
cd ../src
# make clean
make
cd ../tests
# make clean 
make
python3 checker.py