all: sc.bin

sc.bin: sc.o
	aarch64-linux-gnu-objcopy -O binary sc.o sc.bin

sc.o: sc.asm
	aarch64-linux-gnu-as sc.asm -o sc.o

clean:
	rm -rf *o hello
	rm -rf *bin
