 # KSSB force
KSSB_INSTRUMENT := N
KCSAN_SANITIZE := n
KASAN_SANITIZE := n
KCOV_INSTRUMENT := n
UBSAN_SANITIZE := n

ifdef TEST_KSSB
CFLAGS_kssb.o := -D__TEST_KSSB
endif

obj-$(CONFIG_KSSB) += kssb.o kssb_pso.o kssb_context.o kssb_llist.o kssb_profile.o
obj-$(CONFIG_KSSB) += tests/
