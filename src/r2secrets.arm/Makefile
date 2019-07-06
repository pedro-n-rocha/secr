#TOOLCHAIN LOCATION = /usr/local/src/openwrt_agtef_gpl/openwrt_agtef_gpl/staging_dir/toolchain-arm_cortex-a9+neon_gcc-4.8-linaro_uClibc-0.9.33.2_eabi/bin
COMPILER=arm-openwrt-linux-
ARCH=arm
export STAGING_DIR=/usr/local/src/openwrt_agtef_gpl/newtry/openwrt_agtef_gpl/staging_dir

EXTRA_CFLAGS+=-I/usr/local/src/openwrt_agtef_gpl/newtry/openwrt_agtef_gpl/staging_dir/target-arm_cortex-a9+neon_uClibc-0.9.33.2_eabi/usr/include/

obj-m += r2secr.o 

KDIR := /usr/local/src/openwrt_agtef_gpl/newtry/openwrt_agtef_gpl/build_dir/target-arm_cortex-a9+neon_uClibc-0.9.33.2_eabi/linux-brcm63xx-tch/linux-3.4.11

all:
	make  -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) modules

clean:
	make -C  $(KDIR) M=$(PWD) ARCH=$(ARCH) clean
