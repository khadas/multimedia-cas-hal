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

ifeq ($(TARGET_BUILD_VERIMATRIX_SC2_DVB_LIB), true)

include $(CLEAR_VARS)
LOCAL_MODULE := lib_vmx_ree
LOCAL_MULTILIB := 32
LOCAL_MODULE_SUFFIX := .a
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_SRC_FILES_arm := lib/$(LOCAL_MODULE).a
LOCAL_MODULE_TAGS := optional
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := libvmx_dvb
LOCAL_MULTILIB := 32
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := \
    src/vmx_main.c \
    src/vmx_interact.c \
    src/vmx_porting.c \
    src/vmx_chipcert.c \
    src/vmx_smc.c

LOCAL_C_INCLUDES := \
		$(LOCAL_PATH)/include \
		$(LOCAL_PATH)/../libamcas/include \
		$(LOCAL_PATH)/../libcJSON \
		$(LOCAL_PATH)/../liblinuxdvb_port/include \

LOCAL_SHARED_LIBRARIES += liblog \
  libcutils \
  libutils \
  libvmxca_client_sys

LOCAL_STATIC_LIBRARIES += lib_vmx_ree \
  liblinuxdvb_port \
  libcJSON

LOCAL_STRIP_MODULE := false

LOCAL_CFLAGS += -O0 -DANDROID

ifeq ($(shell test $(PLATFORM_SDK_VERSION) -ge 30&& echo OK),OK)
    LOCAL_PROPRIETARY_MODULE := true
    LOCAL_SHARED_LIBRARIES += libsecmem libteec
else
    LOCAL_PRODUCT_MODULE := true
    LOCAL_SHARED_LIBRARIES += libsecmem_sys libteec_sys
endif

include $(BUILD_SHARED_LIBRARY)
endif
