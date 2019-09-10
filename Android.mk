LOCAL_PATH:= $(call my-dir)

#ifeq ($(BUILD_WITH_VIEWRIGHT_DVB),true)

include $(call all-makefiles-under,$(LOCAL_PATH))
  
#endif # ifeq ($(BUILD_WITH_VIEWRIGHT_DVB),true)
