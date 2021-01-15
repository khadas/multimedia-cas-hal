TOPDIR=$(shell pwd)

TARGET=libamcas.a
SRC=$(TOPDIR)/src/am_cas.c
OBJ=$(SRC:.c=.o)

CFLAGS+=-O2 -fPIC -g
CFLAGS+=-I$(TOPDIR)/include

all: $(TARGET)

$(TARGET): $(OBJ)
	@echo "link static library"
	@$(AR) rcs $(TARGET) $(OBJ)

.c.o:
	@echo "compile"
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ) $(TARGET)

