#include <stdio.h>                                      
#include <stdlib.h>
#include <openssl/sha.h>                                

int main(int argc, char **argv){                        
    char buf[20] = {0};                                   
    unsigned int str[4] = {0};                
    unsigned int * rec = (unsigned int *)str;
    unsigned int x0, x1, x2, x3;    
    char tomatch[16] = {0};
    int i;
    size_t l;

    l = read(0, tomatch, 16);

    for(x0 = 0; x0 < 0xffffffff; x0++){

        for(x1 = 0; x1 < 0xffffffff; x1++){

            for(x2 = 0; x2 < 0xffffffff; x2++){

                for(x3 = 0; x3 < 0xffffffff; x3++){
                    str[0] = x0;
                    str[1] = x1;
                    str[2] = x2;
                    str[3] = x3;
                    SHA1((const char *)str, 16, buf);
                    /*
                    for(i = 0; i < 20; i++){
                        printf("%02x", (unsigned char)buf[i]);
                    }
                    printf("\n");*/
                    if(!memcmp(tomatch, buf, l)){
                        printf("input: ");
                        for(i = 0; i < 16; i++){
                            printf("%02x", (unsigned char)(((char *)str)[i]));
                        }
                        printf("\n");
                        printf("output: ");
                        for(i = 0; i < 20; i++){
                            printf("%02x", (unsigned char)buf[i]);
                        }
                        printf("\n");
                        exit(0);
                    }
                        
                }
            }
        }
    }

    return 0;                                       
}                                                       
