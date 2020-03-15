//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#ifndef LIBTGVOIP_MEDIASTREAMINPUT_H
#define LIBTGVOIP_MEDIASTREAMINPUT_H

#include "BlockingQueue.h"
#include "Buffers.h"
#include "threading.h"
#include <memory>
#include <mutex>
#include <cstdint>
#include <cstring>
#include <vector>

namespace tgvoip
{

class EchoCanceller;

class MediaStreamItf
{
public:
    virtual void Start() = 0;
    virtual void Stop() = 0;
    void SetCallback(std::size_t (*f)(unsigned char*, std::size_t, void*), void* param);

    //protected:
    std::size_t InvokeCallback(unsigned char* data, std::size_t length);

    virtual ~MediaStreamItf() = default;

private:
    std::size_t (*callback)(unsigned char*, std::size_t, void*) = NULL;
    std::mutex m_callback;
    void* callbackParam;
};

class AudioMixer : public MediaStreamItf
{
public:
    AudioMixer();
    virtual ~AudioMixer();
    void SetOutput(MediaStreamItf* output);
    virtual void Start();
    virtual void Stop();
    void AddInput(std::shared_ptr<MediaStreamItf> input);
    void RemoveInput(std::shared_ptr<MediaStreamItf> input);
    void SetInputVolume(std::shared_ptr<MediaStreamItf> input, float volumeDB);
    void SetEchoCanceller(EchoCanceller* aec);

private:
    void RunThread();
    struct MixerInput
    {
        std::shared_ptr<MediaStreamItf> source;
        float multiplier;
    };
    Mutex inputsMutex;
    void DoCallback(unsigned char* data, std::size_t length);
    static std::size_t OutputCallback(unsigned char* data, std::size_t length, void* arg);
    std::vector<MixerInput> inputs;
    Thread* thread;
    BufferPool<960 * 2, 16> bufferPool;
    BlockingQueue<Buffer> processedQueue;
    Semaphore semaphore;
    EchoCanceller* echoCanceller;
    bool running;
};

class CallbackWrapper : public MediaStreamItf
{
public:
    CallbackWrapper() {};
    virtual ~CallbackWrapper() {};
    virtual void Start() {};
    virtual void Stop() {};
};

class AudioLevelMeter
{
public:
    AudioLevelMeter();
    float GetLevel();
    void Update(std::int16_t* samples, std::size_t count);

private:
    std::int16_t absMax;
    std::int16_t count;
    std::int8_t currentLevel;
    std::int16_t currentLevelFullRange;
};
};

#endif //LIBTGVOIP_MEDIASTREAMINPUT_H
