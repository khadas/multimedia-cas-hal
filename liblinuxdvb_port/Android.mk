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
LOCAL_MODULE := liblinuxdvb_port
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 SPDX-license-identifier-FTL SPDX-license-identifier-GPL SPDX-license-identifier-GPL-2.0 SPDX-license-identifier-LGPL SPDX-license-identifier-LGPL-2.1 SPDX-license-identifier-MIT legacy_by_exception_only legacy_notice
LOCAL_LICENSE_CONDITIONS := by_exception_only notice restricted
LOCAL_MULTILIB := 32
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := \
    src/am_dmx.c \
    src/am_smc.c \
    src/aml.c \
    src/am_key.c \
    src/am_ca.c

LOCAL_C_INCLUDES := \
		$(LOCAL_PATH) \
		$(LOCAL_PATH)/include \
		$(LOCAL_PATH)/../libamcas/include


LOCAL_SHARED_LIBRARIES += liblog \
  libcutils \
  libutils

LOCAL_CFLAGS += -O0

ifeq ($(shell test $(PLATFORM_SDK_VERSION) -ge 30&& echo OK),OK)
    LOCAL_PROPRIETARY_MODULE := true
endif

include $(BUILD_STATIC_LIBRARY)
