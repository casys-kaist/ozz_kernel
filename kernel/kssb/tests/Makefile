KBUILD_CFLAGS += "-Wno-unused-label"
KSSB_INSTRUMENT := y

CFLAGS_pso_test.o := -mllvm -instrument-out-of-scope=false -O0

obj-y += pso_test.o test.o atomics.o
