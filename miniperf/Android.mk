LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
include external/stlport/libstlport.mk
LOCAL_MODULE       := miniperf-record
LOCAL_MODULE_TAGS  := optional
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES    := miniperf-record.c ehabi_unwind.cpp
LOCAL_CFLAGS       := -DNO_GETLINE -std=gnu++0x
LOCAL_SHARED_LIBRARIES := libstlport
include $(BUILD_EXECUTABLE)
