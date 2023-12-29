OBJS = hello.bpf.o

OPTS = -target bpf -g -O2

CC = clang $(OPTS)
INCLUDE = -I /usr/include/$(shell uname -m)-linux-gnu

.PHONY: all
all: $(OBJS)

%.o: %.c
	$(CC) $(INCLUDE) -c $< -o $@
