obj-$(CONFIG_STING)	+=	dict.o
obj-$(CONFIG_STING)	+=	ept_dict.o
obj-$(CONFIG_STING)	+=	sting.o
obj-$(CONFIG_STING)	+=	syscall_filename.o
obj-$(CONFIG_STING)	+=	permission.o
obj-$(CONFIG_STING) += 	dac_adv_model.o
obj-$(CONFIG_STING) += 	mac_adv_model.o
obj-$(CONFIG_STING)	+=	launch_attack.o
obj-$(CONFIG_STING)	+=	utility.o
obj-$(CONFIG_STING)	+=  shadow_resolution.o
obj-$(CONFIG_STING)	+=	interpreter_unwind.o
obj-$(CONFIG_STING)	+=	userstack/

ccflags-$(CONFIG_STING) := -Ikernel/sting/include -Isecurity/selinux/include -Isecurity/selinux

# CFLAGS_ept_dict.o	:=	-O0
