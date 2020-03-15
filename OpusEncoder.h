//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#ifndef LIBTGVOIP_OPUSENCODER_H
#define LIBTGVOIP_OPUSENCODER_H

#include "BlockingQueue.h"
#include "Buffers.h"
#include "EchoCanceller.h"
#include "MediaStreamItf.h"
#include "threading.h"
#include "utils.h"

#include <atomic>
#include <cstdint>

struct OpusEncoder;

namespace tgvoip
{
class OpusEncoder
{
public:
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(OpusEncoder);
    OpusEncoder(MediaStreamItf* source, bool needSecondary);
    virtual ~OpusEncoder();
    virtual void Start();
    virtual void Stop();
    void SetBitrate(std::uint32_t bitrate);
    void SetEchoCanceller(EchoCanceller* aec);
    void SetOutputFrameDuration(std::uint32_t duration);
    void SetPacketLoss(int percent);
    int GetPacketLoss();
    std::uint32_t GetBitrate();
    void SetDTX(bool enable);
    void SetLevelMeter(AudioLevelMeter* levelMeter);
    void SetCallback(std::function<void(unsigned char*, std::size_t, unsigned char*, std::size_t)> callback);
    void SetSecondaryEncoderEnabled(bool enabled);
    void SetVadMode(bool vad);
    void AddAudioEffect(effects::AudioEffect* effect);
    void RemoveAudioEffect(effects::AudioEffect* effect);
    int GetComplexity()
    {
        return complexity;
    }

private:
    static std::size_t Callback(unsigned char* data, std::size_t len, void* param);
    void RunThread();
    void Encode(std::int16_t* data, std::size_t len);
    void InvokeCallback(unsigned char* data, std::size_t length, unsigned char* secondaryData, std::size_t secondaryLength);
    MediaStreamItf* source;
    ::OpusEncoder* enc;
    ::OpusEncoder* secondaryEncoder;
    unsigned char buffer[4096];
    std::atomic<std::uint32_t> requestedBitrate;
    std::uint32_t currentBitrate;
    Thread* thread;
    BlockingQueue<Buffer> queue;
    BufferPool<960 * 2, 10> bufferPool;
    EchoCanceller* echoCanceller;
    std::atomic<int> complexity;
    std::atomic<bool> running;
    std::uint32_t frameDuration;
    int packetLossPercent;
    AudioLevelMeter* levelMeter;
    std::atomic<bool> secondaryEncoderEnabled;
    bool vadMode = false;
    std::uint32_t vadNoVoiceBitrate;
    std::vector<effects::AudioEffect*> postProcEffects;
    int secondaryEnabledBandwidth;
    int vadModeVoiceBandwidth;
    int vadModeNoVoiceBandwidth;

    bool wasSecondaryEncoderEnabled = false;

    std::function<void(unsigned char*, std::size_t, unsigned char*, std::size_t)> callback;
};
}

#endif //LIBTGVOIP_OPUSENCODER_H
