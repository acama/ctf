CC=diet gcc
APP=x
CFLAGS= -Wall -m32 -O3

app:	
		${CC} ${CFLAGS} x.c -o ${APP}
		strip -s ${APP}
		tar czf x.tar x
		base64 x.tar > x.b64
		rm x.tar

clean:
		rm -rf ${APP} *.o
		rm -rf x.tar
		rm -rf x.b64
