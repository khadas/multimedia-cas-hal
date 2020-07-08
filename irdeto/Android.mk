LOCAL_PATH:= $(call my-dir)

ifeq ($(shell test $(PLATFORM_SDK_VERSION) -ge 26 && echo OK),OK)
OUT_PATH := $(TARGET_OUT_VENDOR)
else
OUT_PATH := $(TARGET_OUT)/
endif

ifeq ($(TARGET_BUILD_IRDETO_CAS_HAL),true)
###########################
include $(CLEAR_VARS)
LOCAL_SRC_FILES      := lib/CloakedCAAgent.lib
LOCAL_MODULE         := CloakedCAAgent
LOCAL_MODULE_SUFFIX  := .a
LOCAL_MODULE_TAGS    := optional
LOCAL_MODULE_CLASS   := STATIC_LIBRARIES
#LOCAL_PROPRIETARY_MODULE := true
include $(BUILD_PREBUILT)

###########################
include $(CLEAR_VARS)
LOCAL_MODULE := libird_dvb
LOCAL_MULTILIB := 32

LOCAL_SRC_FILES := \
	src/ird_client.c \
	src/ird_os.c \
	src/ird_spi.c \
	src/ird_impl.c \
	src/ird_persistent.c \
	src/ird_stream.c \
	src/ird_glue.c \
	src/ird_mail.c \
	src/ird_errorcode.c \

LOCAL_C_INCLUDES := \
  $(LOCAL_PATH)/../libamcas/include	 \
  $(LOCAL_PATH)/../liblinuxdvb_port/include \
  $(LOCAL_PATH)/include              \
  $(LOCAL_PATH)/../libcJSON			\
  $(LOCAL_PATH)/../../../../../../irdeto/irdeto-sdk/include  \

LOCAL_STATIC_LIBRARIES += CloakedCAAgent \
						liblinuxdvb_port \
						libcJSON \

LOCAL_SHARED_LIBRARIES += libz libdl libteec_sys \
						liblog libcutils libutils \
						libirdetoca_sys \

LOCAL_CFLAGS += -O0

#LOCAL_PROPRIETARY_MODULE := true
LOCAL_PRODUCT_MODULE := true

include $(BUILD_SHARED_LIBRARY)

###########################
include $(CLEAR_VARS)
LOCAL_MODULE := ird_test

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_SHARED_LIBRARIES := libird_dvb

LOCAL_SRC_FILES	:= src/ird_test.c

#LOCAL_PROPRIETARY_MODULE := true
LOCAL_PRODUCT_MODULE := true

include $(BUILD_EXECUTABLE)

include $(call all-makefiles-under,$(LOCAL_PATH))
endif

