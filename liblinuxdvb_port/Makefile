TOPDIR=$(shell pwd)

TARGET=liblinuxdvb_port.a
SRC=$(TOPDIR)/src/am_ca.c $(TOPDIR)/src/am_dmx.c \
	$(TOPDIR)/src/am_key.c $(TOPDIR)/src/am_smc.c \
	$(TOPDIR)/src/aml.c

OBJ=$(SRC:.c=.o)

CFLAGS+=-O2 -fPIC -g
CFLAGS+=-I$(TOPDIR)/include -I$(TOPDIR)/../libamcas/include

all: $(TARGET)

$(TARGET): $(OBJ)
	@echo "link static library"
	@$(AR) rcs $(TARGET) $(OBJ)

.c.o:
	@echo "compile"
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ) $(TARGET)

