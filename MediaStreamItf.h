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
#include <unordered_map>
#include <functional>

namespace tgvoip
{

class EchoCanceller;

class MediaStreamItf
{
public:
    virtual void Start() = 0;
    virtual void Stop() = 0;
    void SetCallback(std::function<std::size_t(std::uint8_t*, std::size_t, void*)> f, void* param);

    //protected:
    std::size_t InvokeCallback(std::uint8_t* data, std::size_t length) const;

    virtual ~MediaStreamItf() = default;

private:
    std::function<std::size_t(std::uint8_t*, std::size_t, void*)> m_callback = nullptr;
    mutable std::mutex m_mutexCallback;
    void* m_callbackParam = nullptr;
};

class AudioMixer : public MediaStreamItf
{
public:
    AudioMixer();
    ~AudioMixer() override;
    void SetOutput(MediaStreamItf* output);
    void Start() override;
    void Stop() override;
    void AddInput(std::shared_ptr<MediaStreamItf> input);
    void RemoveInput(std::shared_ptr<MediaStreamItf> input);
    void SetInputVolume(std::shared_ptr<MediaStreamItf> input, float volumeDB);
    void SetEchoCanceller(EchoCanceller* aec);

private:
//    struct MixerInput
//    {
//        std::shared_ptr<MediaStreamItf> source;
//        float multiplier;

//        struct Hash
//        {
//            std::size_t operator()(const MixerInput& value) const noexcept
//            {
//                std::size_t h1 = std::hash<std::shared_ptr<MediaStreamItf>>{}(value.source);
//                std::size_t h2 = std::hash<float>{}(value.multiplier);
//                return h1 ^ (h2 << 1);
//            }
//        };
//    };

    mutable Mutex m_inputsMutex;
    std::unordered_map<std::shared_ptr<MediaStreamItf>, float> m_inputs;
    Thread* m_thread = nullptr;
    BufferPool<960 * 2, 16> m_bufferPool;
    BlockingQueue<Buffer> m_processedQueue;
    Semaphore m_semaphore;
    EchoCanceller* m_echoCanceller = nullptr;
    bool m_running;

    void RunThread();
    void DoCallback(std::uint8_t* data, std::size_t length);
    static std::size_t OutputCallback(std::uint8_t* data, std::size_t length, void* arg);
};

class CallbackWrapper : public MediaStreamItf
{
public:
    CallbackWrapper();
    ~CallbackWrapper() override;
    void Start() override;
    void Stop() override;
};

class AudioLevelMeter
{
public:
    AudioLevelMeter();
    float GetLevel();
    void Update(std::int16_t* samples, std::size_t m_count);

private:
    std::int16_t m_absMax;
    std::int16_t m_count;
    std::int8_t m_currentLevel;
    std::int16_t m_currentLevelFullRange;
};

} // namespace tgvoip

#endif // LIBTGVOIP_MEDIASTREAMINPUT_H
