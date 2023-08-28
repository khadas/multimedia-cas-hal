LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := libaml_dvb
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MULTILIB := both
#LOCAL_ARM_MODE := arm
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

include $(CLEAR_VARS)
LOCAL_MODULE := libdesc_client
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MULTILIB := both
LOCAL_MODULE_SUFFIX := .so
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
#LOCAL_SRC_FILES_arm := lib/$(LOCAL_MODULE).so
LOCAL_SRC_FILES_32 := lib/$(LOCAL_MODULE).so
LOCAL_SRC_FILES_64 := lib64/$(LOCAL_MODULE).so
LOCAL_SHARED_LIBRARIES := libteec liblog
LOCAL_PROPRIETARY_MODULE := true
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := libaml_kl_dvb
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MULTILIB := both
#LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := src/aml_kl_main.c

LOCAL_C_INCLUDES := \
		$(LOCAL_PATH)/include \
		$(LOCAL_PATH)/../libamcas/include \
		$(LOCAL_PATH)/../liblinuxdvb_port/include

LOCAL_SHARED_LIBRARIES += liblog libdesc_client

LOCAL_STATIC_LIBRARIES += \
	liblinuxdvb_port

LOCAL_STRIP_MODULE := false

LOCAL_CFLAGS += -O0 -DANDROID

ifeq ($(shell test $(PLATFORM_SDK_VERSION) -ge 30&& echo OK),OK)
    LOCAL_PROPRIETARY_MODULE := true
endif

include $(BUILD_SHARED_LIBRARY)
