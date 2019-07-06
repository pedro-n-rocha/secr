#ifndef RIP2_CONFIG_H
#define RIP2_CONFIG_H
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <asm/byteorder.h>

extern struct mutex rip2_biglock;

#define ALLOC(size)       kmalloc((size), GFP_KERNEL)
#define FREE(ptr)         kfree((ptr))

#define LOCK()            mutex_lock(&rip2_biglock)
#define UNLOCK()          mutex_unlock(&rip2_biglock)

#define ERR(fmt, ...)     printk(fmt, ## __VA_ARGS__)
#define INFO(fmt, ...)    printk(fmt, ## __VA_ARGS__)
#define DBG(fmt, ...)   printk(fmt, ## __VA_ARGS__)

#ifndef bswap_16
#define bswap_16(x)	__cpu_to_be16(x)
#endif

#ifndef bswap_32
#define bswap_32(x)	__cpu_to_be32(x)
#endif

#endif /* RIP2_CONFIG */
