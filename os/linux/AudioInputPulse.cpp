//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#include "AudioInputPulse.h"
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

using namespace tgvoip::audio;

AudioInputPulse::AudioInputPulse(pa_context* context, pa_threaded_mainloop* mainloop, std::string devID)
    : mainloop(mainloop)
    , context(context)
    , stream(nullptr)
    , isRecording(false)
    , isConnected(false)
    , didStart(false)
    , remainingDataSize(0)
{
    pa_threaded_mainloop_lock(mainloop);

    stream = CreateAndInitStream();
    pa_threaded_mainloop_unlock(mainloop);
    isLocked = false;
    if (stream == nullptr)
    {
        return;
    }

    SetCurrentDevice(std::move(devID));
}

AudioInputPulse::~AudioInputPulse()
{
    if (stream != nullptr)
    {
        pa_stream_disconnect(stream);
        pa_stream_unref(stream);
    }
}

pa_stream* AudioInputPulse::CreateAndInitStream()
{
    pa_sample_spec sampleSpec
    {
        .format = PA_SAMPLE_S16LE,
        .rate = 48000,
        .channels = 1
    };
    pa_proplist* proplist = pa_proplist_new();
    pa_proplist_sets(proplist, PA_PROP_FILTER_APPLY, ""); // according to PA sources, this disables any possible filters
    pa_stream* stream = pa_stream_new_with_proplist(context, "libtgvoip capture", &sampleSpec, nullptr, proplist);
    pa_proplist_free(proplist);
    if (!stream)
    {
        LOGE("Error initializing PulseAudio (pa_stream_new)");
        m_failed = true;
        return nullptr;
    }
    pa_stream_set_state_callback(stream, AudioInputPulse::StreamStateCallback, this);
    pa_stream_set_read_callback(stream, AudioInputPulse::StreamReadCallback, this);
    return stream;
}

void AudioInputPulse::Start()
{
    if (m_failed || isRecording)
        return;

    pa_threaded_mainloop_lock(mainloop);
    isRecording = true;
    pa_operation_unref(pa_stream_cork(stream, 0, nullptr, nullptr));
    pa_threaded_mainloop_unlock(mainloop);
}

void AudioInputPulse::Stop()
{
    if (!isRecording)
        return;

    isRecording = false;
    pa_threaded_mainloop_lock(mainloop);
    pa_operation_unref(pa_stream_cork(stream, 1, nullptr, nullptr));
    pa_threaded_mainloop_unlock(mainloop);
}

bool AudioInputPulse::IsRecording()
{
    return isRecording;
}

void AudioInputPulse::SetCurrentDevice(std::string devID)
{
    pa_threaded_mainloop_lock(mainloop);
    m_currentDevice = std::move(devID);
    if (isRecording && isConnected)
    {
        pa_stream_disconnect(stream);
        pa_stream_unref(stream);
        isConnected = false;
        stream = CreateAndInitStream();
    }

    pa_buffer_attr bufferAttr =
    {
        .maxlength = std::numeric_limits<std::uint32_t>::max(),
        .tlength = std::numeric_limits<std::uint32_t>::max(),
        .prebuf = std::numeric_limits<std::uint32_t>::max(),
        .minreq = std::numeric_limits<std::uint32_t>::max(),
        .fragsize = 960 * 2
    };
    int streamFlags = PA_STREAM_START_CORKED | PA_STREAM_INTERPOLATE_TIMING | PA_STREAM_AUTO_TIMING_UPDATE | PA_STREAM_ADJUST_LATENCY;

    int err = pa_stream_connect_record(stream, m_currentDevice == "default" ? nullptr : m_currentDevice.c_str(), &bufferAttr, (pa_stream_flags_t)streamFlags);
    if (err != 0)
    {
        pa_threaded_mainloop_unlock(mainloop);
        /*if(devID!="default"){
			SetCurrentDevice("default");
			return;
		}*/
    }
    CHECK_ERROR(err, "pa_stream_connect_record");

    while (true)
    {
        pa_stream_state_t streamState = pa_stream_get_state(stream);
        if (!PA_STREAM_IS_GOOD(streamState))
        {
            LOGE("Error connecting to audio device '%s'", m_currentDevice.c_str());
            pa_threaded_mainloop_unlock(mainloop);
            m_failed = true;
            return;
        }
        if (streamState == PA_STREAM_READY)
            break;
        pa_threaded_mainloop_wait(mainloop);
    }

    isConnected = true;

    if (isRecording)
    {
        pa_operation_unref(pa_stream_cork(stream, 0, nullptr, nullptr));
    }
    pa_threaded_mainloop_unlock(mainloop);
}

bool AudioInputPulse::EnumerateDevices(std::vector<AudioInputDevice>& devs)
{
    return AudioPulse::DoOneOperation([&](pa_context* ctx)
    {
        return pa_context_get_source_info_list(
            ctx, [](pa_context* ctx, const pa_source_info* info, int eol, void* userdata)
            {
                if (eol > 0)
                    return;
                std::vector<AudioInputDevice>* devs = reinterpret_cast<std::vector<AudioInputDevice>*>userdata;
                AudioInputDevice dev;
                dev.id = std::string(info->name);
                dev.displayName = std::string(info->description);
                devs->emplace_back(dev);
            },
            &devs);
    });
}

void AudioInputPulse::StreamStateCallback(pa_stream* s, void* arg)
{
    AudioInputPulse* self = reinterpret_cast<AudioInputPulse*>(arg);
    pa_threaded_mainloop_signal(self->mainloop, 0);
}

void AudioInputPulse::StreamReadCallback(pa_stream* stream, std::size_t requestedBytes, void* userdata)
{
    (reinterpret_cast<AudioInputPulse*>(userdata))->StreamReadCallback(stream, requestedBytes);
}

void AudioInputPulse::StreamReadCallback(pa_stream* stream, std::size_t requestedBytes)
{
    std::size_t bytesRemaining = requestedBytes;
    std::uint8_t* buffer = nullptr;
    pa_usec_t latency;
    if (pa_stream_get_latency(stream, &latency, nullptr) == 0)
    {
        m_estimatedDelay = static_cast<std::int32_t>(latency / 100);
    }
    while (bytesRemaining > 0)
    {
        std::size_t bytesToFill = 102400;

        if (bytesToFill > bytesRemaining)
            bytesToFill = bytesRemaining;

        int err = pa_stream_peek(stream, reinterpret_cast<void**>(&buffer), &bytesToFill);
        CHECK_ERROR(err, "pa_stream_peek");

        if (isRecording)
        {
            if (remainingDataSize + bytesToFill > sizeof(remainingData))
            {
                LOGE("Capture buffer is too big (%d)", static_cast<int>(bytesToFill));
            }
            std::memcpy(remainingData + remainingDataSize, buffer, bytesToFill);
            remainingDataSize += bytesToFill;
            while (remainingDataSize >= 960 * 2)
            {
                InvokeCallback(remainingData, 960 * 2);
                memmove(remainingData, remainingData + 960 * 2, remainingDataSize - 960 * 2);
                remainingDataSize -= 960 * 2;
            }
        }

        err = pa_stream_drop(stream);
        CHECK_ERROR(err, "pa_stream_drop");

        bytesRemaining -= bytesToFill;
    }
}
