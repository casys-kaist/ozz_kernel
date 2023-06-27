KBUILD_CFLAGS += "-Wno-unused-label"
# KSSB force
KSSB_INSTRUMENT := y

CFLAGS_pso_test.o := -mllvm -instrument-out-of-scope=false
CFLAGS_tso_test.o := -mllvm -instrument-out-of-scope=false

obj-y += pso_test.o atomics.o tso_test.o
