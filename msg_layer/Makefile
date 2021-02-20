ifeq ($(KERNELRELEASE),)
KERNELDIR := ..
PWD := $(shell pwd)
include $(KERNELDIR)/.config
endif

#obj-$(CONFIG_POPCORN_KMSG) += msg_init.o
#msg_init-y := msg_init.o ring_buffer.o

obj-m += msg_layer_main.o 
obj-m += ring_buffer.o
msg_layer-y := msg_layer_main.o ring_buffer.o

obj-$(CONFIG_POPCORN_KMSG_RDMA) += msg_rdma.o
msg_rdma-y := rdma.o ring_buffer.o

#obj-$(CONFIG_POPCORN_KMSG_IB) += msg_ib.o
#msg_ib-y := ib.o

obj-$(CONFIG_POPCORN_KMSG_TEST) += msg_test.o

.PHONY: modules
modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
ifdef CONFIG_POPCORN_KMSG_DOLPHIN
	$(MAKE) -C dolphin modules
endif

.PHONY: modules_install
modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
ifdef CONFIG_POPCORN_KMSG_DOLPHIN
	$(MAKE) -C dolphin modules_install
endif

.PHONY: clean
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	$(MAKE) -C dolphin clean