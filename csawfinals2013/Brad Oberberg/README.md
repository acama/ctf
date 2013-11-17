#Description

Not sure exactly what the module does, but it's a misc device that does things with structs, arrays, linked lists and stuff.
        
##The vulnerability

We have the following relevant code excerpts:
```c        
#define MAX_CONSUMERS 255

struct csaw_buf {
    unsigned long consumers[MAX_CONSUMERS]; // [1]
    char *buf;
    unsigned long size;
    unsigned long seed;
    struct list_head list;
};
```
```c 
case CSAW_SET_CONSUMER:
{
    struct consumer_args consumer_args;
    struct csaw_buf *cbuf;
    unsigned int i, authorized = 0;

    if ( copy_from_user(&consumer_args, argp, sizeof(consumer_args)) )
    return -EFAULT;

    cbuf = find_cbuf(consumer_args.handle);
    if ( ! cbuf )
    return -EINVAL;

    for ( i = 0; i < MAX_CONSUMERS; i++ )
    if ( current->pid == cbuf->consumers[i] )
    authorized = 1;

    if ( ! authorized )
    return -EPERM;

    cbuf->consumers[consumer_args.offset] = consumer_args.pid; // [2]

    break;
}
```
```c
struct consumer_args {
    unsigned long handle;
    unsigned long pid;
    unsigned char offset;
};
```
```c
case CSAW_WRITE_HANDLE:
{
    struct write_args write_args;
    struct csaw_buf *cbuf;
    unsigned int i, authorized = 0;
    unsigned long to_write;

    if ( copy_from_user(&write_args, argp, sizeof(write_args)) )
        return -EFAULT;

    cbuf = find_cbuf(write_args.handle);
    if ( ! cbuf )
        return  -EINVAL;

    for ( i = 0; i < MAX_CONSUMERS; i++ )
        if ( current->pid == cbuf->consumers[i] )
            authorized = 1;

    if ( ! authorized )
        return -EPERM;

    to_write = min(write_args.size, cbuf->size);

    if ( copy_from_user(cbuf->buf, write_args.in, to_write) ) // [3]
        return -EFAULT;

    bytes_written += to_write;

    break;
}
```

At [1] we see that *csaw_buf.consumers* array is of length 255 but at [2] we see that *consumer_args.offset* is a unsigned char meaning (i.e its value can range from 0 to 255).
The user controls the value of consumer_args.offset and consumer_args.pid so this means that we can overwrite whatever is just
after the *csaw_buf.consumers* array which turns out to be *csaw_buf.buf*, a pointer we can write to and read from.
At [3] we can write into *cbuf->buf* whatver is *write_args.in* (which we also control)
All in all, this is an **arbitrary write** (and read for that matter) vulnerability. Michael was very kind to have this type of vuln and not some of the other less pleasant types of vulnerabilities.

##The obstacles around the vulnerability
        
There's a few things we have to do and take care of before we can actually trigger the overwrite.
Through the module, some checks are performed. 
When we create/allocate a handle, the function *alloc_buf()* is called which at some point
does the following:
        
```c
cbuf->consumers[0] = current->pid; // [1]

get_random_bytes(&seed, sizeof(seed));

cbuf->seed = seed;

handle = (unsigned long)buf ^ seed; // [2]

list_add(&cbuf->list, &csaw_bufs);

alloc_args->handle = handle;
```

At [1] it puts our current pid at *csaw_buf.consumers[0]* and the associated check that is performed 
throughout the module is:

```c       
for ( i = 0; i < MAX_CONSUMERS; i++ )
        if ( current->pid == cbuf->consumers[i] )
            authorized = 1;

if ( ! authorized )
        return -EPERM;
```

This check we don't have to worry about because it will pass unless we overwrite that consumers[0] value, 
which we have no use in overwriting.

At [2], the second and trickier associated check is the one performed in *find_cbuf()* which does:
       
```c
list_for_each_entry ( cbuf, &csaw_bufs, list )
    if ( handle == ((unsigned long)cbuf->buf ^ cbuf->seed) )
        return cbuf;

return NULL; 
```

This is a problem because we are going to overwrite *cbuf->buf* and so the handle calculated at [2] in alloc buf will be different from won't match.

To overcome this we need to find a way to get *cbuf->seed and* then we can recalculate the new handle since we control the value of *cbuf->buf* (thanks to the overwrite).


##The exploit
        
So the exploitation works as follows:
* create a cbuf using *CSAW_ALLOC_HANDLE* and get its associated handle
* use the index-too-large vuln (or whatever you want to call it) to read the value of *cbuf->buf* with *CSAW_GET_CONSUMER*
* *cbuf->buf ^ handle* to get the value of the seed
* now we can call *CSAW_SET_CONSUMER* and using the index-too-large vuln, we overwrite *cbuf->buf* with *arbitrary_ptr*
* *arbitrary_ptr ^ seed* to get the new handle
* now we call *CSAW_WRITE_HANDLE* to trigger the arbitrary write

I chose to overwrite the [*dnotify_fsnotify_ops.should_send_event*](http://lxr.free-electrons.com/source/include/linux/fsnotify_backend.h#L96) ptr. Note that it's not too reliable to overwrite this
because there might be other programs on the box using dnotify. I took my chances, still.
    
Compile the exploit with gcc exploit.c -o exploit
We get the pretty '#' and the flag is key{help_im_trapped_in_an_exploit_sweatshop}

Thanks Michael C. for the best challenge of the CTF!
