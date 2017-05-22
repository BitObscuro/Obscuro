local_c_flags :=

local_c_includes :=

local_additional_dependencies := $(LOCAL_PATH)/android-config.mk $(LOCAL_PATH)/Crypto.mk

include $(LOCAL_PATH)/Crypto-config.mk

#######################################
# target static library
include $(SGX_CLEAR_VARS)
include $(LOCAL_PATH)/android-config.mk

LOCAL_SHARED_LIBRARIES :=

# If we're building an unbundled build, don't try to use clang since it's not
# in the NDK yet. This can be removed when a clang version that is fast enough
# in the NDK.
ifeq (,$(TARGET_BUILD_APPS))
LOCAL_CLANG := true
else
LOCAL_SDK_VERSION := 9
endif

LOCAL_SRC_FILES += $(target_src_files)
LOCAL_CFLAGS += $(target_c_flags)
LOCAL_C_INCLUDES += $(target_c_includes)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE:= libcrypto
LOCAL_ADDITIONAL_DEPENDENCIES := $(local_additional_dependencies)
#include $(BUILD_STATIC_LIBRARY)
include $(SGX_STATIC_TRUSTED)
