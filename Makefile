obj-m += vaclog.o
vaclog-objs := src/main.o src/hooks.o src/hook_handlers.o src/scantrack.o
MCFLAGS += -g -O0
ccflags-y += ${MCFLAGS}
CC += ${MCFLAGS}

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
