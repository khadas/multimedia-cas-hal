LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	cas_hal_test.c

LOCAL_C_INCLUDES := \
		$(LOCAL_PATH) \
		$(LOCAL_PATH)/../includes.dir \
		$(LOCAL_PATH)/../libamcas \
		system/media/audio/include \
		frameworks/av/include \
		hardware/amlogic/media/amcodec/include \

LOCAL_SHARED_LIBRARIES := liblog libteec

LOCAL_STATIC_LIBRARIES += \
  libutils \
  libcaclientapi \
  libam_cas \
  libvmx_dvb \
  libvmx_ree_dual_aml \
  libcaclientapi

LOCAL_STATIC_LIBRARIES += libcutils


	
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE:= cas_hal_test


#LOCAL_PROPRIETARY_MODULE := true

#include $(BUILD_EXECUTABLE)


  










