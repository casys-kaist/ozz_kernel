KSSB_INSTRUMENT := y
export KSSB_INSTRUMENT

ccflags-y += -I $(srctree)/arch/x86/kvm
ccflags-$(CONFIG_KVM_WERROR) += -Werror


obj-$(CONFIG_KVM)			+= kvm_main.o coalesced_mmio.o \
				eventfd.o irqchip.o vfio.o \
				dirty_ring.o binary_stats.o
obj-$(CONFIG_KVM_ASYNC_PF)	+= async_pf.o
