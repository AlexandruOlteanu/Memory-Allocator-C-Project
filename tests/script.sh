#!/bin/bash
cd ../src
make
cd ../tests
make
python3 checker.py