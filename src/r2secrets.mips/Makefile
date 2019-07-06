COMPILER=mips-openwrt-linux-
ARCH=mips

obj-m += r2secr.o

export STAGING_DIR=/usr/local/src/openwrt_vant-6_gpl/staging_dir/


ccflags-y := -DCC_HAVE_ASM_GOTO -DUSE_IMMEDIATE  

KDIR := /usr/local/src/openwrt_vant-6_gpl/build_dir/target-mips_mips32_uClibc-0.9.33.2/linux-brcm63xx-tch_VANTF/linux-3.4.11/

all:
	make  -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) modules

clean:
	make -C  $(KDIR) M=$(PWD) ARCH=$(ARCH) clean
