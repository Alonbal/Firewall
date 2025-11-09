obj-m += firewall.o
firewall-m := hw5secws.o rules.o log.o inspection.o conns.o mitm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean