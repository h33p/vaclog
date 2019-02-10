obj-m += vaclog.o
CBDIR = kbuild
vaclog-objs := ${CBDIR}/main.o ${CBDIR}/hooks.o ${CBDIR}/hook_handlers.o ${CBDIR}/scantrack.o ${CBDIR}/vacdump.o ${CBDIR}/fs_access.o
MCFLAGS += -Ofast
ccflags-y += ${MCFLAGS}
CC += ${MCFLAGS}

ifneq ($(CBDIR), src)
all:
	$(shell mkdir ${CBDIR})
	$(shell cp -r src/* ${CBDIR}/)
	sh name_mangler.sh ${CBDIR}/
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -r ${CBDIR}/*
	rmdir ${CBDIR}

else
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
endif
