/*
 *                      .ed"""" """$$$$be.
 *                    -"           ^""**$$$e.
 *                  ."                   '$$$c
 *                 /     C S A W          "4$$b
 *                d  3      2 0 1 3         $$$$
 *                $  *                   .$$$$$$
 *               .$  ^c           $$$$$e$$$$$$$$.
 *               d$L  4.         4$$$$$$$$$$$$$$b
 *               $$$$b ^ceeeee.  4$$ECL.F*$$$$$$$
 *   e$""=.      $$$$P d$$$$F $ $$$$$$$$$- $$$$$$
 *  z$$b. ^c     3$$$F "$$$$b   $"$$$$$$$  $$$$*"      .=""$c
 * 4$$$$L        $$P"  "$$b   .$ $$$$$...e$$        .=  e$$$.
 * ^*$$$$$c  %..   *c    ..    $$ 3$$$$$$$$$$eF     zP  d$$$$$
 *   "**$$$ec   "   %ce""    $$$  $$$$$$$$$$*    .r" =$$$$P""
 *         "*$b.  "c  *$e.    *** d$$$$$"L$$    .d"  e$$***"
 *           ^*$$c ^$c $$$      4J$$$$$% $$$ .e*".eeP"
 *              "$$$$$$"'$=e....$*$$**$cz$$" "..d$*"
 *                "*$$$  *=%4.$ L L$ P3$$$F $$$P"
 *                   "$   "%*ebJLzb$e$$$$$b $P"
 *                     %..      4$$$$$$$$$$ "
 *                      $$$e   z$$$$$$$$$$%
 *                       "*$c  "$$$$$$$P"
 *                        ."""*$$$$$$$$bc
 *                     .-"    .$***$$$"""*e.
 *                  .-"    .e$"     "*$c  ^*b.
 *           .=*""""    .e$*"          "*bc  "*$e..
 *         .$"        .z*"               ^*$e.   "*****e.
 *         $$ee$c   .d"                     "*$.        3.
 *         ^*$E")$..$"                         *   .ee==d%
 *            $.d$$$*                           *  J$$$e*
 *             """""                              "$$$" Gilo95'
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

#define DRIVER_VERSION "CSAW SUCKiT v1.3.37"

#define CSAW_IOCTL_BASE     0x77617363
#define CSAW_ALLOC_HANDLE   CSAW_IOCTL_BASE+1
#define CSAW_READ_HANDLE    CSAW_IOCTL_BASE+2
#define CSAW_WRITE_HANDLE   CSAW_IOCTL_BASE+3
#define CSAW_GET_CONSUMER   CSAW_IOCTL_BASE+4
#define CSAW_SET_CONSUMER   CSAW_IOCTL_BASE+5
#define CSAW_FREE_HANDLE    CSAW_IOCTL_BASE+6
#define CSAW_GET_STATS	    CSAW_IOCTL_BASE+7

#define MAX_CONSUMERS 255

struct csaw_buf {
    unsigned long consumers[MAX_CONSUMERS];
    char *buf;
    unsigned long size;
    unsigned long seed;
    struct list_head list;
};

LIST_HEAD(csaw_bufs);

struct alloc_args {
    unsigned long size;
    unsigned long handle;
};

struct free_args {
    unsigned long handle;
};

struct read_args {
    unsigned long handle;
    unsigned long size;
    void *out;
};

struct write_args {
    unsigned long handle;
    unsigned long size;
    void *in;
};

struct consumer_args {
    unsigned long handle;
    unsigned long pid;
    unsigned char offset;
};

struct csaw_stats {
    unsigned long clients;
    unsigned long handles;
    unsigned long bytes_read;
    unsigned long bytes_written;
    char version[40];
};

unsigned long clients = 0;
unsigned long handles = 0;
unsigned long bytes_read = 0;
unsigned long bytes_written = 0;

static int csaw_open ( struct inode *inode, struct file *file )
{
    clients++;

    return 0;
}

static int csaw_release ( struct inode *inode, struct file *file )
{
    clients--;

    return 0;
}

int alloc_buf ( struct alloc_args *alloc_args )
{
    struct csaw_buf *cbuf;
    char *buf;
    unsigned long size, seed, handle;

    size = alloc_args->size;

    if ( ! size )
        return -EINVAL;

    cbuf = kmalloc(sizeof(*cbuf), GFP_KERNEL);
    if ( ! cbuf )
        return -ENOMEM;

    buf = kzalloc(size, GFP_KERNEL);
    if ( ! buf )
    {
        kfree(cbuf);
        return -ENOMEM;
    }

    cbuf->buf = buf;
    cbuf->size = size;

    memset(&cbuf->consumers, 0, sizeof(cbuf->consumers));
    cbuf->consumers[0] = current->pid;

    get_random_bytes(&seed, sizeof(seed));

    cbuf->seed = seed;

    handle = (unsigned long)buf ^ seed;

    list_add(&cbuf->list, &csaw_bufs);

    alloc_args->handle = handle;

    return 0;
}

void free_buf ( struct csaw_buf *cbuf )
{
    list_del(&cbuf->list);
    kfree(cbuf->buf);
    kfree(cbuf);
}

struct csaw_buf *find_cbuf ( unsigned long handle )
{
    struct csaw_buf *cbuf;

    list_for_each_entry ( cbuf, &csaw_bufs, list )
        if ( handle == ((unsigned long)cbuf->buf ^ cbuf->seed) )
            return cbuf;

    return NULL;
}

static long csaw_ioctl ( struct file *file, unsigned int cmd, unsigned long arg )
{
    int ret = 0;
    unsigned long *argp = (unsigned long *)arg;

    switch ( cmd )
    {
        case CSAW_ALLOC_HANDLE:
        {
            int ret;
            struct alloc_args alloc_args;

            if ( copy_from_user(&alloc_args, argp, sizeof(alloc_args)) )
                return -EFAULT;

            if ( (ret = alloc_buf(&alloc_args)) < 0 )
                return ret;

            if ( copy_to_user(argp, &alloc_args, sizeof(alloc_args)) )
                return -EFAULT;

            handles++;

            break;
        }

        case CSAW_READ_HANDLE:
        {
            struct read_args read_args;
            struct csaw_buf *cbuf;
            unsigned int i, authorized = 0;
            unsigned long to_read;

            if ( copy_from_user(&read_args, argp, sizeof(read_args)) )
                return -EFAULT;

            cbuf = find_cbuf(read_args.handle);
            if ( ! cbuf )
                return -EINVAL;

            for ( i = 0; i < MAX_CONSUMERS; i++ )
                if ( current->pid == cbuf->consumers[i] )
                    authorized = 1;

            if ( ! authorized )
                return -EPERM;

            to_read = min(read_args.size, cbuf->size);

            if ( copy_to_user(read_args.out, cbuf->buf, to_read) )
                return -EFAULT;

            bytes_read += to_read;

            break;
        }

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

            if ( copy_from_user(cbuf->buf, write_args.in, to_write) )
                return -EFAULT;

            bytes_written += to_write;

            break;
        }

        case CSAW_GET_CONSUMER:
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

            consumer_args.pid = cbuf->consumers[consumer_args.offset];

            if ( copy_to_user(argp, &consumer_args, sizeof(consumer_args)) )
                return -EFAULT;

            break;
        }

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

            cbuf->consumers[consumer_args.offset] = consumer_args.pid; // user controls consumer_args.offset "off by one indexing"

            break;
        }

        case CSAW_FREE_HANDLE:
        {
            struct free_args free_args;
            struct csaw_buf *cbuf;
            unsigned int i, authorized = 0;

            if ( copy_from_user(&free_args, argp, sizeof(free_args)) )
                return -EFAULT;

            cbuf = find_cbuf(free_args.handle);
            if ( ! cbuf )
                return -EINVAL;

            for ( i = 0; i < MAX_CONSUMERS; i++ )
                if ( current->pid == cbuf->consumers[i] )
                    authorized = 1;

            if ( ! authorized )
                return -EPERM;

            free_buf(cbuf);

            handles--;

            break;
        }

        case CSAW_GET_STATS:
        {
            struct csaw_stats csaw_stats;

            csaw_stats.clients = clients;
            csaw_stats.handles = handles;
            csaw_stats.bytes_read = bytes_read;
            csaw_stats.bytes_written = bytes_written;
            strcpy(csaw_stats.version, DRIVER_VERSION);

            if ( copy_to_user(argp, &csaw_stats, sizeof(csaw_stats)) )
                return -EFAULT;

            break;
        }

        default:
            ret = -EINVAL;
            break;
    }

    return ret;
}

static ssize_t csaw_read ( struct file *file, char *buf, size_t count, loff_t *pos )
{
    char *stats;
    unsigned int to_read;
    unsigned int ret;

    stats = kmalloc(1024, GFP_KERNEL);
    if ( ! buf )
        return -ENOMEM;

    ret = snprintf(stats, 1024, "Active clients: %lu\nHandles allocated: %lu\nBytes read: %lu\nBytes written: %lu\n",
             clients, handles, bytes_read, bytes_written);

    if ( count < ret )
        to_read = count;
    else
        to_read = ret;

    if ( copy_to_user(buf, stats, to_read) )
    {
        kfree(stats);
        return -EFAULT;
    }

    kfree(stats);

    return 0;
}

static const struct file_operations csaw_fops = {
    owner:          THIS_MODULE,
    open:           csaw_open,
    release:        csaw_release,
    unlocked_ioctl: csaw_ioctl,
    read:           csaw_read,
};

static struct miscdevice csaw_miscdev = {
    name:   "csaw",
    fops:   &csaw_fops
};

static int __init lezzdoit ( void )
{
    misc_register(&csaw_miscdev);

    return 0;
}

static void __exit wereouttahurr ( void )
{
    misc_deregister(&csaw_miscdev);
}

module_init(lezzdoit);
module_exit(wereouttahurr);

MODULE_LICENSE("GPL");
