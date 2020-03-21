//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#include "AudioOutputALSA.h"
#include "../../VoIPController.h"
#include "../../logging.h"
#include <cassert>
#include <dlfcn.h>

#define BUFFER_SIZE 960
#define CHECK_ERROR(res, msg)                 \
    if (res < 0)                              \
    {                                         \
        LOGE(msg ": %s", _snd_strerror(res)); \
        failed = true;                        \
        return;                               \
    }
#define CHECK_DL_ERROR(res, msg)     \
    if (!res)                        \
    {                                \
        LOGE(msg ": %s", dlerror()); \
        failed = true;               \
        return;                      \
    }
#define LOAD_FUNCTION(lib, name, ref)                               \
    {                                                               \
        ref = (typeof(ref))dlsym(lib, name);                        \
        CHECK_DL_ERROR(ref, "Error getting entry point for " name); \
    }

using namespace tgvoip::audio;

AudioOutputALSA::AudioOutputALSA(std::string devID)
{
    m_isPlaying = false;
    m_handle = nullptr;

    m_lib = dlopen("libasound.so.2", RTLD_LAZY);
    if (!m_lib)
        m_lib = dlopen("libasound.so", RTLD_LAZY);
    if (!m_lib)
    {
        LOGE("Error loading libasound: %s", dlerror());
        m_failed = true;
        return;
    }

    LOAD_FUNCTION(m_lib, "snd_pcm_open", m_snd_pcm_open);
    LOAD_FUNCTION(m_lib, "snd_pcm_set_params", m_snd_pcm_set_params);
    LOAD_FUNCTION(m_lib, "snd_pcm_close", m_snd_pcm_close);
    LOAD_FUNCTION(m_lib, "snd_pcm_writei", m_snd_pcm_writei);
    LOAD_FUNCTION(m_lib, "snd_pcm_recover", m_snd_pcm_recover);
    LOAD_FUNCTION(m_lib, "snd_strerror", m_snd_strerror);

    SetCurrentDevice(devID);
}

AudioOutputALSA::~AudioOutputALSA()
{
    if (m_handle)
        m_snd_pcm_close(m_handle);
    if (m_lib)
        dlclose(m_lib);
}

void AudioOutputALSA::Start()
{
    if (m_failed || m_isPlaying)
        return;

    m_isPlaying = true;
    m_thread = new Thread(std::bind(&AudioOutputALSA::RunThread, this));
    m_thread->SetName("AudioOutputALSA");
    m_thread->Start();
}

void AudioOutputALSA::Stop()
{
    if (!m_isPlaying)
        return;

    m_isPlaying = false;
    m_thread->Join();
    delete m_thread;
    m_thread = nullptr;
}

bool AudioOutputALSA::IsPlaying()
{
    return m_isPlaying;
}
void AudioOutputALSA::RunThread()
{
    std::uint8_t buffer[BUFFER_SIZE * 2];
    snd_pcm_sframes_t frames;
    while (m_isPlaying)
    {
        InvokeCallback(buffer, sizeof(buffer));
        frames = m_snd_pcm_writei(m_handle, buffer, BUFFER_SIZE);
        if (frames < 0)
        {
            frames = m_snd_pcm_recover(m_handle, frames, 0);
        }
        if (frames < 0)
        {
            LOGE("snd_pcm_writei failed: %s\n", m_snd_strerror(frames));
            break;
        }
    }
}

void AudioOutputALSA::SetCurrentDevice(std::string devID)
{
    bool wasPlaying = m_isPlaying;
    m_isPlaying = false;
    if (m_handle)
    {
        m_thread->Join();
        m_snd_pcm_close(m_handle);
    }
    m_currentDevice = devID;

    int res = m_snd_pcm_open(&m_handle, devID.c_str(), SND_PCM_STREAM_PLAYBACK, 0);
    if (res < 0)
        res = m_snd_pcm_open(&m_handle, "default", SND_PCM_STREAM_PLAYBACK, 0);
    CHECK_ERROR(res, "snd_pcm_open failed");

    res = m_snd_pcm_set_params(m_handle, SND_PCM_FORMAT_S16, SND_PCM_ACCESS_RW_INTERLEAVED, 1, 48000, 1, 100000);
    CHECK_ERROR(res, "snd_pcm_set_params failed");

    if (wasPlaying)
    {
        m_isPlaying = true;
        m_thread->Start();
    }
}

void AudioOutputALSA::EnumerateDevices(std::vector<AudioOutputDevice>& devs)
{
    int (*_snd_device_name_hint)(int card, const char* iface, void*** hints);
    char* (*_snd_device_name_get_hint)(const void* hint, const char* id);
    int (*_snd_device_name_free_hint)(void** hinst);
    void* lib = dlopen("libasound.so.2", RTLD_LAZY);
    if (!lib)
        dlopen("libasound.so", RTLD_LAZY);
    if (!lib)
        return;

    _snd_device_name_hint = (typeof(_snd_device_name_hint))dlsym(lib, "snd_device_name_hint");
    _snd_device_name_get_hint = (typeof(_snd_device_name_get_hint))dlsym(lib, "snd_device_name_get_hint");
    _snd_device_name_free_hint = (typeof(_snd_device_name_free_hint))dlsym(lib, "snd_device_name_free_hint");

    if (!_snd_device_name_hint || !_snd_device_name_get_hint || !_snd_device_name_free_hint)
    {
        dlclose(lib);
        return;
    }

    char** hints;
    int err = _snd_device_name_hint(-1, "pcm", (void***)&hints);
    if (err != 0)
    {
        dlclose(lib);
        return;
    }

    char** n = hints;
    while (*n)
    {
        char* name = _snd_device_name_get_hint(*n, "NAME");
        if (strncmp(name, "surround", 8) == 0 || strcmp(name, "null") == 0)
        {
            std::free(name);
            n++;
            continue;
        }
        char* desc = _snd_device_name_get_hint(*n, "DESC");
        char* ioid = _snd_device_name_get_hint(*n, "IOID");
        if (!ioid || strcmp(ioid, "Output") == 0)
        {
            char* l1 = strtok(desc, "\n");
            char* l2 = strtok(nullptr, "\n");
            char* tmp = strtok(l1, ",");
            char* actualName = tmp;
            while ((tmp = strtok(nullptr, ",")))
            {
                actualName = tmp;
            }
            if (actualName[0] == ' ')
                actualName++;
            AudioOutputDevice dev;
            dev.id = std::string(name);
            if (l2)
            {
                char buf[256];
                snprintf(buf, sizeof(buf), "%s (%s)", actualName, l2);
                dev.displayName = std::string(buf);
            }
            else
            {
                dev.displayName = std::string(actualName);
            }
            devs.push_back(dev);
        }
        std::free(name);
        std::free(desc);
        std::free(ioid);
        n++;
    }

    dlclose(lib);
}
