
CC?=	gcc
CFLAGS+=	-Wall -Werror -lpcap

all:
	${CC} ${CFLAGS} bpf_comp.c -o bpf_comp
