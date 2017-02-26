/*
 * Bootstrap code for newlib functions
*/

#include <stddef.h>
#include <sys/stat.h>
#include "newlibstrap.h"
#include "syscalldefs.h"
#include "strap.h"

int _close(int file){ 
    (void)file;
    return -1; 
}

int _fstat(int file, struct stat *st){
    (void)file;
    st->st_mode = S_IFCHR;
    return 0;
}

int _isatty(int file){ 
    (void)file;
    return 1; 
}

int _lseek(int file, int ptr, int dir){ 
    (void)file;
    (void)ptr;
    (void)dir;
    return 0; 
}

int _open(const char *name, int flags, int mode){ 
    (void)flags;
    (void)name;
    (void)mode;
    return -1; 
}

int _read(int file, char *ptr, int len){
    (void)file;
    DO_SWI(ISYS_READ, ptr, len);
    return len;
}

int _write(int file, char *ptr, int len){
    (void)file;
    DO_SWI(ISYS_WRITE, ptr, len);
    return len;
}

char *heap_end = 0;
caddr_t _sbrk(int incr){
    extern char heap_low; //[> Defined by the linker <]
    extern char heap_top; //[> Defined by the linker <]
    char *prev_heap_end;

    if (heap_end == 0) {
        heap_end = &heap_low;
    }
    prev_heap_end = heap_end;

    if (heap_end + incr > &heap_top) {
        /*[> Heap and stack collision <]*/
        return (caddr_t)0;
    }

    heap_end += incr;
    return (caddr_t) prev_heap_end;
}

