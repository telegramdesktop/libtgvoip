//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#include "AudioOutputPulse.h"
#include "../../VoIPController.h"
#include "../../logging.h"
#include "AudioPulse.h"
#include "PulseFunctions.h"
#include <cassert>
#include <dlfcn.h>
#include <unistd.h>
#if !defined(__GLIBC__)
#include <libgen.h>
#endif

#define BUFFER_SIZE 960
#define CHECK_ERROR(res, msg)                      \
    if (res != 0)                                  \
    {                                              \
        LOGE(msg " failed: %s", pa_strerror(res)); \
        failed = true;                             \
        return;                                    \
    }

using namespace tgvoip;
using namespace tgvoip::audio;

AudioOutputPulse::AudioOutputPulse(pa_context* context, pa_threaded_mainloop* mainloop, std::string devID)
{
    isPlaying = false;
    isConnected = false;
    didStart = false;
    isLocked = false;

    this->mainloop = mainloop;
    this->context = context;
    stream = nullptr;
    remainingDataSize = 0;

    pa_threaded_mainloop_lock(mainloop);
    stream = CreateAndInitStream();
    pa_threaded_mainloop_unlock(mainloop);

    SetCurrentDevice(devID);
}

AudioOutputPulse::~AudioOutputPulse()
{
    if (stream)
    {
        pa_stream_disconnect(stream);
        pa_stream_unref(stream);
    }
}

pa_stream* AudioOutputPulse::CreateAndInitStream()
{
    pa_sample_spec sampleSpec
    {
        .format = PA_SAMPLE_S16LE,
        .rate = 48000,
        .channels = 1
    };
    pa_proplist* proplist = pa_proplist_new();
    pa_proplist_sets(proplist, PA_PROP_FILTER_APPLY, ""); // according to PA sources, this disables any possible filters
    pa_stream* stream = pa_stream_new_with_proplist(context, "libtgvoip playback", &sampleSpec, nullptr, proplist);
    pa_proplist_free(proplist);
    if (stream == nullptr)
    {
        LOGE("Error initializing PulseAudio (pa_stream_new)");
        m_failed = true;
        return nullptr;
    }
    pa_stream_set_state_callback(stream, AudioOutputPulse::StreamStateCallback, this);
    pa_stream_set_write_callback(stream, AudioOutputPulse::StreamWriteCallback, this);
    return stream;
}

void AudioOutputPulse::Start()
{
    if (m_failed || isPlaying)
        return;

    isPlaying = true;
    pa_threaded_mainloop_lock(mainloop);
    pa_operation_unref(pa_stream_cork(stream, 0, nullptr, nullptr));
    pa_threaded_mainloop_unlock(mainloop);
}

void AudioOutputPulse::Stop()
{
    if (!isPlaying)
        return;

    isPlaying = false;
    pa_threaded_mainloop_lock(mainloop);
    pa_operation_unref(pa_stream_cork(stream, 1, nullptr, nullptr));
    pa_threaded_mainloop_unlock(mainloop);
}

bool AudioOutputPulse::IsPlaying()
{
    return isPlaying;
}

void AudioOutputPulse::SetCurrentDevice(std::string devID)
{
    pa_threaded_mainloop_lock(mainloop);
    m_currentDevice = std::move(devID);
    if (isPlaying && isConnected)
    {
        pa_stream_disconnect(stream);
        pa_stream_unref(stream);
        isConnected = false;
        stream = CreateAndInitStream();
    }

    pa_buffer_attr bufferAttr =
    {
        .maxlength = std::numeric_limits<std::uint32_t>::max(),
        .tlength = 960 * 2,
        .prebuf = std::numeric_limits<std::uint32_t>::max(),
        .minreq = std::numeric_limits<std::uint32_t>::max(),
        .fragsize = std::numeric_limits<std::uint32_t>::max()
    };
    int streamFlags = PA_STREAM_START_CORKED | PA_STREAM_INTERPOLATE_TIMING | PA_STREAM_AUTO_TIMING_UPDATE | PA_STREAM_ADJUST_LATENCY;

    int err = pa_stream_connect_playback(stream, devID == "default" ? nullptr : devID.c_str(), &bufferAttr, static_cast<pa_stream_flags_t>(streamFlags), nullptr, nullptr);
    if (err != 0 && devID != "default")
    {
        SetCurrentDevice("default");
        return;
    }
    CHECK_ERROR(err, "pa_stream_connect_playback");

    while (true)
    {
        pa_stream_state_t streamState = pa_stream_get_state(stream);
        if (!PA_STREAM_IS_GOOD(streamState))
        {
            LOGE("Error connecting to audio device '%s'", devID.c_str());
            m_failed = true;
            return;
        }
        if (streamState == PA_STREAM_READY)
            break;
        pa_threaded_mainloop_wait(mainloop);
    }

    isConnected = true;

    if (isPlaying)
    {
        pa_operation_unref(pa_stream_cork(stream, 0, nullptr, nullptr));
    }
    pa_threaded_mainloop_unlock(mainloop);
}

bool AudioOutputPulse::EnumerateDevices(std::vector<AudioOutputDevice>& devs)
{
    return AudioPulse::DoOneOperation([&](pa_context* ctx)
    {
        return pa_context_get_sink_info_list(
            ctx, [](pa_context* ctx, const pa_sink_info* info, int eol, void* userdata)
            {
                if (eol > 0)
                    return;
                std::vector<AudioOutputDevice>* devs = reinterpret_cast<std::vector<AudioOutputDevice>*>(userdata);
                AudioOutputDevice dev;
                dev.id = std::string(info->name);
                dev.displayName = std::string(info->description);
                devs->push_back(dev);
            },
            &devs);
    });
}

void AudioOutputPulse::StreamStateCallback(pa_stream* s, void* arg)
{
    AudioOutputPulse* self = reinterpret_cast<AudioOutputPulse*>(arg);
    pa_threaded_mainloop_signal(self->mainloop, 0);
}

void AudioOutputPulse::StreamWriteCallback(pa_stream* stream, std::size_t requestedBytes, void* userdata)
{
    (reinterpret_cast<AudioOutputPulse*>(userdata))->StreamWriteCallback(stream, requestedBytes);
}

void AudioOutputPulse::StreamWriteCallback(pa_stream* stream, std::size_t requestedBytes)
{
    //assert(requestedBytes<=sizeof(remainingData));
    if (requestedBytes > sizeof(remainingData))
    {
        requestedBytes = 960 * 2; // force buffer size to 20ms. This probably wrecks the jitter buffer, but still better than crashing
    }
    pa_usec_t latency;
    if (pa_stream_get_latency(stream, &latency, nullptr) == 0)
    {
        m_estimatedDelay = static_cast<std::int32_t>(latency / 100);
    }
    while (requestedBytes > remainingDataSize)
    {
        if (isPlaying)
        {
            InvokeCallback(remainingData + remainingDataSize, 960 * 2);
            remainingDataSize += 960 * 2;
        }
        else
        {
            std::memset(remainingData + remainingDataSize, 0, requestedBytes - remainingDataSize);
            remainingDataSize = requestedBytes;
        }
    }
    int err = pa_stream_write(stream, remainingData, requestedBytes, nullptr, 0, PA_SEEK_RELATIVE);
    CHECK_ERROR(err, "pa_stream_write");
    remainingDataSize -= requestedBytes;
    if (remainingDataSize > 0)
        memmove(remainingData, remainingData + requestedBytes, remainingDataSize);
}
