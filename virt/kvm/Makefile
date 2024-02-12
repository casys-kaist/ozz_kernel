KSSB_INSTRUMENT := y
export KSSB_INSTRUMENT

ccflags-y += -I $(srctree)/arch/x86/kvm
ccflags-$(CONFIG_KVM_WERROR) += -Werror


# obj-$(CONFIG_KVM)			+= kvm_main.o coalesced_mmio.o \
# 				eventfd.o irqchip.o vfio.o \
# 				dirty_ring.o binary_stats.o
# obj-$(CONFIG_KVM_ASYNC_PF)	+= async_pf.o

obj-y := kvm_main.o eventfd.o binary_stats.o
obj-$(CONFIG_KVM_VFIO) += vfio.o
obj-$(CONFIG_KVM_MMIO) += coalesced_mmio.o
obj-$(CONFIG_KVM_ASYNC_PF) += async_pf.o
obj-$(CONFIG_HAVE_KVM_IRQ_ROUTING) += irqchip.o
obj-$(CONFIG_HAVE_KVM_DIRTY_RING) += dirty_ring.o
obj-$(CONFIG_HAVE_KVM_PFNCACHE) += pfncache.o
obj-$(CONFIG_KVM_PRIVATE_MEM) += guest_memfd.o
