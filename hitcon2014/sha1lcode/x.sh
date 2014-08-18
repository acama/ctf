#!/bin/sh
(./printdata.py; cat -) | nc 210.61.2.51 5566
