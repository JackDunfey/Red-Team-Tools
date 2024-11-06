# Makefile for building a simple kernel module
obj-m += arpk.o  # Replace arp_filter with the name of your module file without the .c extension

# Path to the kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Default target to build the module
all: handler
	$(MAKE) -C $(KDIR) M=$(PWD) modules

handler:
	gcc arp_handler.c -o /root/arp_handler

# Target to clean up build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
