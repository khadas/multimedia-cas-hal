LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := libcJSON
ifeq ($(shell test $(PLATFORM_SDK_VERSION) -ge 32&& echo OK),OK)
LOCAL_LICENSE_KINDS := SPDX-license-identifier-MIT
LOCAL_LICENSE_CONDITIONS := notice
endif
LOCAL_MULTILIB := both
#LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := cJSON.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_CFLAGS += -O0

ifeq ($(shell test $(PLATFORM_SDK_VERSION) -ge 30&& echo OK), OK)
LOCAL_VENDOR_MODULE := true
endif

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libcJSON_sys
ifeq ($(shell test $(PLATFORM_SDK_VERSION) -ge 32&& echo OK),OK)
LOCAL_LICENSE_KINDS := SPDX-license-identifier-MIT
LOCAL_LICENSE_CONDITIONS := notice
endif
LOCAL_MULTILIB := 32
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := cJSON.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_CFLAGS += -O0

include $(BUILD_STATIC_LIBRARY)
