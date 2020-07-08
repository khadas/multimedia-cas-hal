LOCAL_PATH := $(call my-dir)

$(info --- TARGET_OUT_VENDOR: $(TARGET_OUT_VENDOR))

###################### cloaked_ca_1.dat ######################
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := cloaked_ca_1
LOCAL_MODULE_SUFFIX := .dat
LOCAL_MODULE_CLASS := PREPARE_DATA
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/etc/cas/irdeto/cadata/
LOCAL_SRC_FILES := cloaked_ca_1.dat
include $(BUILD_PREBUILT)

###################### cloaked_ca_9.dat ######################
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := cloaked_ca_9
LOCAL_MODULE_SUFFIX := .dat
LOCAL_MODULE_CLASS := PREPARE_DATA
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/etc/cas/irdeto/cadata/
LOCAL_SRC_FILES := cloaked_ca_9.dat
include $(BUILD_PREBUILT)

###################### cloaked_ca_62.dat #### Watermark ######
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := cloaked_ca_62
LOCAL_MODULE_SUFFIX := .dat
LOCAL_MODULE_CLASS := PREPARE_DATA
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/etc/cas/irdeto/cadata/
LOCAL_SRC_FILES := cloaked_ca_62.dat
include $(BUILD_PREBUILT)

###################### cloaked_ca_72.dat #### Watermark ######
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := cloaked_ca_72
LOCAL_MODULE_SUFFIX := .dat
LOCAL_MODULE_CLASS := PREPARE_DATA
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/etc/cas/irdeto/cadata/
LOCAL_SRC_FILES := cloaked_ca_72.dat
include $(BUILD_PREBUILT)
