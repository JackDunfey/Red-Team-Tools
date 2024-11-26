CONFIG_MODULE_SIG=n
# obj-m += icmpk.o
obj-m += hide_service.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
