all: sc.bin

sc.bin: sc.asm
	nasm sc.asm -o sc.bin -DFILENAME=\"/home/callme/flag\" -DSIZE=0x40

clean:
	rm -rf *o hello
	rm -rf *bin
