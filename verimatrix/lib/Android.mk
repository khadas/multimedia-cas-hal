LOCAL_PATH:= $(call my-dir)


#############################################################
include $(CLEAR_VARS)
LOCAL_MODULE := libcaclientapi
LOCAL_MULTILIB := 32
LOCAL_MODULE_SUFFIX := .a
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_SRC_FILES_arm := $(LOCAL_MODULE).a
LOCAL_MODULE_TAGS := optional
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := libvmx_ree_dual_aml
LOCAL_MULTILIB := 32
LOCAL_MODULE_SUFFIX := .a
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_SRC_FILES_arm := $(LOCAL_MODULE).a
LOCAL_MODULE_TAGS := optional
#include $(BUILD_PREBUILT)
