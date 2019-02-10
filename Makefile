obj-m += vaclog.o
CBDIR = src
vaclog-objs := ${CBDIR}/main.o ${CBDIR}/hooks.o ${CBDIR}/hook_handlers.o ${CBDIR}/scantrack.o ${CBDIR}/vacdump.o ${CBDIR}/fs_access.o
MCFLAGS += -Ofast
ccflags-y += ${MCFLAGS}
CC += ${MCFLAGS}

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
