LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

ifeq ($(SUPPORT_CAS), true)
LOCAL_SRC_FILES:= \
	cas_hal_test.c \
    cas_scan.c

LOCAL_C_INCLUDES := \
        $(LOCAL_PATH)/../libamcas/include \
        $(LOCAL_PATH)/../liblinuxdvb_port/include \
        vendor/amlogic/common/prebuilt/dvb/include/am_adp \
        vendor/amlogic/common/libdvr/include \
        vendor/amlogic/common/mediahal_sdk/include

LOCAL_SHARED_LIBRARIES := liblog libteec_sys libmediahal_tsplayer.system libamdvr.product

LOCAL_STATIC_LIBRARIES += \
  libutils \
  libam_cas \
  liblinuxdvb_port \
  libam_adp

LOCAL_STATIC_LIBRARIES += libcutils
	
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE:= cas_hal_test

#LOCAL_PROPRIETARY_MODULE := true

include $(BUILD_EXECUTABLE)
endif
