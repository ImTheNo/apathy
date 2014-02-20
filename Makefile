obj-m := sad_droid.o

hostprogs-m += apathy_test
hostprogs-m += apathy_test2

KDIR 	?= $(shell uname -r)
#KPATH 	?= /usr/src/linux-headers-$(KDIR)
KBDIR	?= /lib/modules/$(KDIR)/build

ccflags-y := -I$(KBDIR)/security/selinux -I$(KBDIR)/security/selinux/include

PWD := $(shell pwd)

default:
	$(MAKE) -C $(KBDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KBDIR) SUBDIRS=$(PWD) clean

__build: $(hostprogs-m)
