//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#ifndef LIBTGVOIP_OPUSDECODER_H
#define LIBTGVOIP_OPUSDECODER_H

#include "BlockingQueue.h"
#include "Buffers.h"
#include "EchoCanceller.h"
#include "JitterBuffer.h"
#include "MediaStreamItf.h"
#include "threading.h"
#include "utils.h"
#include <atomic>
#include <memory>
#include <cstdio>
#include <vector>

struct OpusDecoder;

namespace tgvoip
{

class OpusDecoder
{
public:
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(OpusDecoder);
    virtual void Start();
    virtual void Stop();

    OpusDecoder(const std::shared_ptr<MediaStreamItf>& dst, bool isAsync, bool needEC);
    OpusDecoder(const std::unique_ptr<MediaStreamItf>& dst, bool isAsync, bool needEC);
    OpusDecoder(MediaStreamItf* dst, bool isAsync, bool needEC);
    virtual ~OpusDecoder();
    std::size_t HandleCallback(unsigned char* data, std::size_t len);
    void SetEchoCanceller(EchoCanceller* canceller);
    void SetFrameDuration(std::uint32_t duration);
    void SetJitterBuffer(std::shared_ptr<JitterBuffer> m_jitterBuffer);
    void SetDTX(bool enable);
    void SetLevelMeter(AudioLevelMeter* m_levelMeter);
    void AddAudioEffect(effects::AudioEffect* effect);
    void RemoveAudioEffect(effects::AudioEffect* effect);

private:
    ::OpusDecoder* m_dec;
    ::OpusDecoder* m_ecDec;
    BlockingQueue<Buffer>* m_decodedQueue;
    BufferPool<960 * 2, 32> m_bufferPool;
    unsigned char* m_buffer;
    unsigned char* m_lastDecoded;
    unsigned char* m_processedBuffer;
    std::size_t m_outputBufferSize;
    std::atomic<bool> m_running;
    Thread* m_thread;
    Semaphore* m_semaphore;
    std::uint32_t m_frameDuration;
    EchoCanceller* m_echoCanceller;
    std::shared_ptr<JitterBuffer> m_jitterBuffer;
    AudioLevelMeter* m_levelMeter;
    int m_consecutiveLostPackets;
    bool m_enableDTX;
    std::size_t m_silentPacketCount;
    std::vector<effects::AudioEffect*> m_postProcEffects;
    std::atomic<bool> m_async;
    alignas(2) unsigned char m_nextBuffer[8192];
    alignas(2) unsigned char m_decodeBuffer[8192];
    std::size_t m_nextLen;
    unsigned int m_packetsPerFrame;
    std::ptrdiff_t m_remainingDataLen;
    bool m_prevWasEC;
    std::int16_t m_prevLastSample;

    void Initialize(bool isAsync, bool needEC);
    void RunThread();
    int DecodeNextFrame();
    static std::size_t Callback(unsigned char* data, std::size_t len, void* param);
};

} // namespace tgvoip

#endif // LIBTGVOIP_OPUSDECODER_H
