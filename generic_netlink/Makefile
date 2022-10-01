KERNEL=/usr/src/linux-headers-$(shell uname -r)/
obj-m+=nav_genl.o

all:
	make -C $(KERNEL) M=$(PWD) modules
	$(CC) userspace.c -o userspace $(INCLUDES) $(LIBS)

clean:
	make -C $(KERNEL) M=$(PWD) clean
	rm -rf userspace
