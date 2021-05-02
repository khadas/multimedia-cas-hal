LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := libaml_dvb
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 SPDX-license-identifier-BSD SPDX-license-identifier-LGPL legacy_by_exception_only
LOCAL_LICENSE_CONDITIONS := by_exception_only notice restricted
LOCAL_MULTILIB := 32
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := src/aml_main.c

LOCAL_C_INCLUDES := \
		$(LOCAL_PATH)/include \
		$(LOCAL_PATH)/../libamcas/include \
		$(LOCAL_PATH)/../liblinuxdvb_port/include

LOCAL_SHARED_LIBRARIES += liblog

LOCAL_STATIC_LIBRARIES += \
	liblinuxdvb_port

LOCAL_STRIP_MODULE := false

LOCAL_CFLAGS += -O0 -DANDROID

ifeq ($(shell test $(PLATFORM_SDK_VERSION) -ge 30&& echo OK),OK)
    LOCAL_PROPRIETARY_MODULE := true
endif

include $(BUILD_SHARED_LIBRARY)

