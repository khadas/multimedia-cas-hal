OUTPUT_FILES := libcJSON.a liblinuxdvb_port.a libamcas.a cas_hal_test_bin

OUT_DIR ?= .
$(info "OUT_DIR : $(OUT_DIR)")

CFLAGS  := -Wall -O2 -fPIC -IlibcJSON -Ilibamcas/include -Iliblinuxdvb_port/include -I$(STAGING_DIR)/usr/include/libdvr
LDFLAGS := -L$(OUT_DIR) -L$(TARGET_DIR)/usr/lib -lamdvr -lmediahal_tsplayer -laudio_client -llog -lpthread -ldl

LIBCJSON_SRCS := libcJSON/cJSON.c
LIBCJSON_OBJS := $(patsubst %.c,%.o,$(LIBCJSON_SRCS))
ALL_OBJS += $(LIBCJSON_OBJS)

LIBLINUXDVB_PORT_SRCS := \
	liblinuxdvb_port/src/am_ca.c\
	liblinuxdvb_port/src/am_dmx.c\
	liblinuxdvb_port/src/am_key.c\
	liblinuxdvb_port/src/aml.c\
	liblinuxdvb_port/src/am_smc.c
LIBLINUXDVB_PORT_OBJS := $(patsubst %.c,%.o,$(LIBLINUXDVB_PORT_SRCS))
ALL_OBJS += $(LIBLINUXDVB_PORT_OBJS)

LIBAMCAS_SRCS := libamcas/src/am_cas.c
LIBAMCAS_OBJS := $(patsubst %.c,%.o,$(LIBAMCAS_SRCS))
ALL_OBJS += $(LIBAMCAS_OBJS)

CAS_HAL_TEST_SRCS := \
	cas_hal_test/cas_hal_test.c\
	cas_hal_test/dvr_playback.c\
	cas_hal_test/fend.c\
	cas_hal_test/scan.c
CAS_HAL_TEST_OBJS := $(patsubst %.c,%.o,$(CAS_HAL_TEST_SRCS))
ALL_OBJS += $(CAS_HAL_TEST_OBJS)

all: $(OUTPUT_FILES)

%.o: %.c
	$(CC) -c -o $(OUT_DIR)/$@ $< $(CFLAGS)

libcJSON.a: $(LIBCJSON_OBJS)
	$(AR) rcs $(OUT_DIR)/$@ $(patsubst %, $(OUT_DIR)/%, $^)

liblinuxdvb_port.a: $(LIBLINUXDVB_PORT_OBJS)
	$(AR) rcs $(OUT_DIR)/$@ $(patsubst %, $(OUT_DIR)/%, $^)

libamcas.a: $(LIBAMCAS_OBJS)
	$(AR) rcs $(OUT_DIR)/$@ $(patsubst %, $(OUT_DIR)/%, $^)

cas_hal_test_bin: $(CAS_HAL_TEST_OBJS) libcJSON.a liblinuxdvb_port.a libamcas.a
	$(CC) -o $(OUT_DIR)/$@ $(patsubst %, $(OUT_DIR)/%, $(CAS_HAL_TEST_OBJS)) -L. -lamcas -lcJSON -llinuxdvb_port $(LDFLAGS)

install: $(OUTPUT_FILES)
	install -m 0755 $(OUT_DIR)/libamcas.a $(STAGING_DIR)/usr/lib
	install -d -m 0755 $(STAGING_DIR)/usr/include/libamcas
	install -m 0644 ./libamcas/include/* $(STAGING_DIR)/usr/include/libamcas
	install -m 0755 $(OUT_DIR)/cas_hal_test_bin $(STAGING_DIR)/usr/bin

clean:
	rm -f $(patsubst %, $(OUT_DIR)/%, $(ALL_OBJS))
	rm -f $(patsubst %, $(OUT_DIR)/%, $(OUTPUT_FILES))

.PHONY: all install clean

$(shell mkdir -p $(OUT_DIR)/liblinuxdvb_port/src)
$(shell mkdir -p $(OUT_DIR)/libamcas/src)
$(shell mkdir -p $(OUT_DIR)/libcJSON)
$(shell mkdir -p $(OUT_DIR)/cas_hal_test)
