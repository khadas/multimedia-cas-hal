# Copyright (C) 2008 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Copyright The Android Open Source Project

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := libaml_enc_dvb
LOCAL_MULTILIB := 32
LOCAL_ARM_MODE := arm
LOCAL_FILE_LIST := $(wildcard $(LOCAL_PATH)/*.c)
LOCAL_SRC_FILES := $(LOCAL_FILE_LIST:$(LOCAL_PATH)/%=%)

LOCAL_C_INCLUDES := \
		$(LOCAL_PATH)/include \
		$(LOCAL_PATH)/../libamcas/include

LOCAL_SHARED_LIBRARIES += liblog libcutils libutils

ifeq ($(shell test $(PLATFORM_SDK_VERSION) -eq 29 && echo OK),OK)
    LOCAL_PRODUCT_MODULE := true
else
    LOCAL_VENDOR_MODULE := true
endif

LOCAL_PRELINK_MODULE := false
include $(BUILD_SHARED_LIBRARY)
