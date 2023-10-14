#!make

LIB    := nlp.so
SRCS   := link.c neigh.c addr.c route.c
OBJS   := link.o neigh.o addr.o route.o
LDLIBS := $(shell pkg-config --libs   libnl-route-3.0 libnl-3.0)
LDLIBS += -lev
CFLAGS := $(shell pkg-config --cflags libnl-route-3.0 libnl-3.0)
CFLAGS += -I./headers
CFLAGS += -g -Og -fPIC -W -Wall -Wextra -Wno-unused-parameter

all: $(LIB)

$(LIB): $(OBJS)
	$(CC) -shared -o lib$@ $^ $(LDLIBS)
	$(RM) $(OBJS)

clean:
	$(RM) *.o *.so *~ *.bak
