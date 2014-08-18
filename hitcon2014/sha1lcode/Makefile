all: brutus sc.bin

sc.bin: sc.asm
	nasm sc.asm -o sc.bin

brutus: brutus.c
	gcc brutus.c -o brutus -lcrypto

clean:
	rm -rf brutus
	rm -rf *o hello
	rm -rf *bin
