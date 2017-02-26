#include <stdint.h>
#include <stddef.h>
#include "strap.h"
#include "syscalldefs.h"

int iwrite(char * buf, size_t len){
    return DO_SWI(ISYS_WRITE, buf, len);
}

int iread(char * buf, size_t len){
    return DO_SWI(ISYS_READ, buf, len);
}

int read_until(char * buf, size_t n){
    size_t i = 0;

    for(i = 0; i < n - 1; i++){
        char c = 0;
        DO_SWI(ISYS_READ, &c, 1);
        if(c == 0x0d || c == 0x0a){
            buf[i] = c;  
            break;
        }
        buf[i] = c;
    }
    buf[i] = 0;
    return i;
}

void iexit(){
    DO_SWI(ISYS_EXIT);
}

void iexecve(uint8_t * bin, size_t binsize){
    DO_SWI(ISYS_EXECVE, bin, binsize);
}

unsigned int irand(){
    return DO_SWI(ISYS_RAND);
}
