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
LOCAL_MODULE := libvmx_dvb
LOCAL_MULTILIB := 32
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := \
    vmx_main.c \
    vmx_porting.c

LOCAL_C_INCLUDES := \
		$(LOCAL_PATH) \
		$(LOCAL_PATH)/../libamcas \
		$(LOCAL_PATH)/../includes.dir \
		$(LOCAL_PATH)/../libcaclientapi/include \
		vendor/amlogic/common/external/dvb/include/am_adp \
		vendor/amlogic/common/external/dvb/android/ndk/include \
		vendor/amlogic/common/external/dvb/android/ndk/include/linux \
		

LOCAL_SHARED_LIBRARIES += liblog \
  libcutils \
  libutils \
  libteec \
  libam_adp

LOCAL_STATIC_LIBRARIES += libvmx_ree libcaclientapi

LOCAL_CFLAGS += -O0 -DANDROID

LOCAL_PROPRIETARY_MODULE := true

include $(BUILD_SHARED_LIBRARY) 
