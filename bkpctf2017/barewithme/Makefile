ARMGNU ?= arm-none-eabi

AARCH = -march=armv7ve
AOPS = --warn --fatal-warnings $(AARCH)
COPS = -Wall -Wextra -O2 -nostdlib -nostartfiles -ffreestanding -fno-delete-null-pointer-checks -fno-isolate-erroneous-paths-dereference -fPIC -fPIE $(AARCH)

main.bin :  asm.o newlibstrap.o kstub.bin kpayload.bin main.o stage1.bin
	$(ARMGNU)-ld asm.o newlibstrap.o main.o ./libc.a ./libgcc.a -T script.ld -o main.elf
	$(ARMGNU)-objcopy main.elf -O binary sc.bin

asm.o : asm.s
	$(ARMGNU)-as $(AOPS) asm.s -o asm.o

stage1.bin : stage1.asm
	$(ARMGNU)-as $(AOPS) stage1.asm -o stage1.elf
	$(ARMGNU)-objcopy stage1.elf -O binary stage1.bin

kstub.bin : kstub.asm
	$(ARMGNU)-as $(AOPS) kstub.asm -o kstub.elf
	$(ARMGNU)-objcopy kstub.elf -O binary kstub.bin
	xxd -i kstub.bin > kstub.h

kpayload.bin : kpayload.asm
	$(ARMGNU)-as $(AOPS) kpayload.asm -o kpayload.elf
	$(ARMGNU)-objcopy kpayload.elf -O binary kpayload.bin
	xxd -i kpayload.bin > kpayload.h

main.o : main.c 
	$(ARMGNU)-gcc -c $(COPS) main.c -o main.o

newlibstrap.o : newlibstrap.c 
	$(ARMGNU)-gcc -c $(COPS) newlibstrap.c -o newlibstrap.o

clean :
	rm -f *.o
	rm -f *.elf
	rm -f *.bin
	rm -f *.list
	rm -f calc.h
	rm -f trader.h
	rm -f echo.h
	rm -f library.h
	rm -rf userspace.h
	rm -rf kstub.h
	rm -rf kpayload.h
