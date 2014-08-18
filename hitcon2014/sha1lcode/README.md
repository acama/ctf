HITCON CTF 2014 sha1lcode Challenge
============================

This is the code for the exploit I wrote for the HITCON 2014 sha1lcode challenge. A writeup of this challenge can be found [here]()
First build the shellcode with:
```
make
```
Then run the exploit with:
```
./x.sh
```
The "brutus" program is a program that given some bytes, will bruteforce to find a 16 byte buffer whose SHA1 starts with (or is equal to) those given bytes.
