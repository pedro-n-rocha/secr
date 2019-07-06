#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>

#include "include/rip_ids.h"
#include "include/rip2_crypto.h"


#define __ASM_ARCH_MEMORY_H
#define PHYS_OFFSET	UL(0x00000000)
static inline void * rip2_crypto_phys_to_virt (void *p)
{
    return (void*)(phys_to_virt((unsigned long)p));
}


void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printk("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printk(" ");
			if ((i+1) % 16 == 0) {
				printk("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printk(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printk("   ");
				}
				printk("|  %s \n", ascii);
			}
		}
	}
}


static int __init k_module_init(void)
{
    extern unsigned char *r2secr;
		unsigned char * data_ptr; 
    Rip2Secrets *r2secr_struct = (Rip2Secrets *)(rip2_crypto_phys_to_virt(r2secr));

		printk("r2secr : %lx \n" , (unsigned long ) r2secr ) ;
		printk("r2secr_struct : %lx \n" , (unsigned long ) r2secr_struct ) ;
		printk("r2secr_struct->magic : %lx \n" , (unsigned long ) r2secr_struct->magic ) ;
		printk("r2secr_struct->items : %lx \n" , (unsigned long ) r2secr_struct->items ) ;

		Rip2SecretsItem *nextFreeItem = r2secr_struct->items;

		while(nextFreeItem->id != 0 ){
	
			printk("nextFreeItem->id : %x \n" , nextFreeItem->id ) ;
			printk("nextFreeItem->length : %d \n" , nextFreeItem->length ) ;
			printk("nextFreeItem->data : %lx \n" ,(unsigned long) nextFreeItem->data ) ;
			data_ptr = rip2_crypto_phys_to_virt(nextFreeItem->data);

			printk("data_ptr : %lx \n" ,(unsigned long) data_ptr ) ;
			DumpHex(data_ptr,nextFreeItem->length);
			
			//for( i = 0 ; i < nextFreeItem->length ; i++ ) 
			//	printk("%x",nextFreeItem->data[i]);

			++nextFreeItem;
		}

	return 0; 
}

static void __exit k_module_cleanup(void)
{
	printk(KERN_INFO "module cleanup \n");
}

module_init(k_module_init);
module_exit(k_module_cleanup);
MODULE_LICENSE("GPL");
