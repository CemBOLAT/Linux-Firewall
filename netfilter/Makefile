# Makefile for the character device driver

obj-m += my_net.o
 
all: # symbolic link to kernel !!!!
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
