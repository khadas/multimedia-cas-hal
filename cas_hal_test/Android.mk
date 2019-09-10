LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	cas_hal_test.c

LOCAL_C_INCLUDES := \
		$(LOCAL_PATH) \
		$(LOCAL_PATH)/../includes.dir \
		$(LOCAL_PATH)/../libamcas \
		vendor/amlogic/common/external/dvb/include/am_adp \
		vendor/amlogic/common/external/dvb/android/ndk/include \
		vendor/amlogic/common/external/dvb/android/ndk/include/linux \
		system/media/audio/include \
		frameworks/av/include \
		hardware/amlogic/media/amcodec/include \

LOCAL_SHARED_LIBRARIES := libam_adp liblog libteec

LOCAL_STATIC_LIBRARIES += \
  libcutils \
  libutils \
  libam_cas

	
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE:= cas_hal_test


LOCAL_PROPRIETARY_MODULE := true

include $(BUILD_EXECUTABLE)


  










