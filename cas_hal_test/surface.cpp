/*
 * Copyright (c) 2020 Amlogic, Inc. All rights reserved.
 *
 * This source code is subject to the terms and conditions defined in the
 * file 'LICENSE' which is part of this source code package.
 *
 * Description:
 */
#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif
#include <fstream>
#include <unistd.h>
#include <sys/time.h>
#include <cstdlib>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <thread>
#include <atomic>
#include <map>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include <chrono>
#include <sys/time.h>
#include <memory>
#include <getopt.h>
#include <chrono>
#include <AmTsPlayer.h>
#include <termios.h>
#include <pthread.h>

#include <amlogic/am_gralloc_ext.h>

#include <gui/IProducerListener.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/ISurfaceComposer.h>

#if ANDROID_PLATFORM_SDK_VERSION <= 30
#include <ui/DisplayInfo.h>
#endif
#include "am_cas.h"

using namespace android;
using namespace std;

/*TS Playback Switch*/
typedef enum {
    TS_PLAYBACK_DISABLE = 0,    // Not playback when file eof
    TS_PLAYBACK_ENABLE = 1,     // Playback when file eof
} am_tsplayer_playback_type;

am_tsplayer_handle session;
const int kRwSize = 188*300;
const int kRwTimeout = 30000;

#define DEBUG_FLAG 1
#define TEST_FLOW 0
bool enable_thread;

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

/*
ANDROID_PLATFORM_SDK_VERSION = 30 --> Android R
ANDROID_PLATFORM_SDK_VERSION = 29 --> Android Q
ANDROID_PLATFORM_SDK_VERSION = 28 --> Android P
*/

//system lib

android::sp<SurfaceComposerClient> mComposerClient = NULL;
android::sp<SurfaceControl> mControl = NULL;
android::sp<Surface> mSurface = NULL;

sp<IProducerListener> mProducerListener = NULL;
sp<IGraphicBufferProducer> mProducer = NULL;
sp<NativeHandle> mSourceHandle = NULL;
native_handle_t * mNative_handle = NULL;

extern "C" bool CreateVideoTunnelId(int* id);

bool CreateVideoTunnelId(int* id) {
    int x = 0, y = 0, w = 0, h = 0;
    int tunnelId = 0;
    x = 0;
    y = 0;
    w = 960;
    h = 540;

    if (mSurface == NULL) {
        mComposerClient = new SurfaceComposerClient;
        if (mComposerClient->initCheck() != 0) {
            return false;
        }

        mProducerListener = new StubProducerListener;

        char test[20];
        sprintf(test,"testSurface_%d",tunnelId);
        CA_DEBUG( 1, "CreateVideoTunnelId name:%s \n",test);
        mControl = mComposerClient->createSurface(String8(test),
                                                  w,
                                                  h,
                                                  HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED);
        if (mControl == NULL) {
            CA_DEBUG( 1, "mControl == NULL");
            return false;
        }
        if (!mControl->isValid()) {
            CA_DEBUG( 1, "! mControl->isValid  no ");
            return false;
        }
        SurfaceComposerClient::Transaction{}
        .setLayer(mControl, 0)
        .setFlags(mControl, android::layer_state_t::eLayerOpaque, android::layer_state_t::eLayerOpaque)
        .show(mControl)
        .setPosition(mControl, x, y)
        .apply();
        mSurface = mControl->getSurface();
        if (mSurface == NULL) {
            CA_DEBUG( 1, "mSurface == NULL");
            return false;
        }

        mSurface->connect(NATIVE_WINDOW_API_CPU, mProducerListener);

        if (mSurface) {
            mProducer = mSurface->getIGraphicBufferProducer();
            if (mNative_handle == NULL) {
                mNative_handle = am_gralloc_create_sideband_handle(AM_FIXED_TUNNEL, tunnelId);
                CA_DEBUG( 1, "mNative_handle:%p\n",mNative_handle);
            }
            if (mNative_handle != NULL) {
                mSourceHandle = NativeHandle::create(mNative_handle, false);
            }
            if (mProducer != NULL && mSourceHandle != NULL) {
                mProducer->setSidebandStream(mSourceHandle);
                CA_DEBUG( 1, "setSidebandStream is called!\n");
            }
            CA_DEBUG( 1, "----->tunnelId:%d\n",tunnelId);
            *id = tunnelId;
        }
    }
    return true;
}

