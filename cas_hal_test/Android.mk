LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

ifeq ($(SUPPORT_CAS), true)
LOCAL_SRC_FILES:= \
	cas_hal_test.c \
	dvr_playback.c \
	scan.c \
	fend.c

LOCAL_C_INCLUDES := \
        $(LOCAL_PATH)/../libamcas/include \
        $(LOCAL_PATH)/../libcJSON \
        $(LOCAL_PATH)/../liblinuxdvb_port/include \
        vendor/amlogic/common/prebuilt/dvb/include/am_adp \
        vendor/amlogic/common/libdvr_release/include \
        vendor/amlogic/common/mediahal_sdk/include

LOCAL_SHARED_LIBRARIES := liblog
LOCAL_STATIC_LIBRARIES += \
    libutils \
    libcJSON \
    libam_cas \
    liblinuxdvb_port \
    libcutils

ifeq ($(shell test $(PLATFORM_SDK_VERSION) -ge 30&& echo OK),OK)
    LOCAL_SHARED_LIBRARIES += libteec libmediahal_tsplayer libamdvr
    LOCAL_PROPRIETARY_MODULE := true
else
    LOCAL_SHARED_LIBRARIES += libteec_sys libmediahal_tsplayer.system libamdvr.product
endif

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE:= cas_hal_test
LOCAL_LICENSE_KINDS:= SPDX-license-identifier-Apache-2.0 SPDX-license-identifier-BSD SPDX-license-identifier-LGPL legacy_by_exception_only
LOCAL_LICENSE_CONDITIONS:= by_exception_only notice restricted

include $(BUILD_EXECUTABLE)
endif
