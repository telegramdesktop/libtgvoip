//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#ifndef LIBTGVOIP_JITTERBUFFER_H
#define LIBTGVOIP_JITTERBUFFER_H

#include "BlockingQueue.h"
#include "Buffers.h"
#include "MediaStreamItf.h"
#include "threading.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <vector>

#define JITTER_SLOT_COUNT 64
#define JITTER_SLOT_SIZE 1024

namespace tgvoip
{

class JitterBuffer
{
public:
    JitterBuffer(MediaStreamItf* out, std::uint32_t m_step);
    ~JitterBuffer();
    void SetMinPacketCount(std::uint32_t count);
    int GetMinPacketCount();
    unsigned int GetCurrentDelay();
    double GetAverageDelay();
    void Reset();
    void HandleInput(unsigned char* data, std::size_t len, std::uint32_t timestamp, bool isEC);
    std::size_t HandleOutput(unsigned char* buffer, std::size_t len, int offsetInSteps, bool advance, int& playbackScaledDuration, bool& isEC);
    void Tick();
    void GetAverageLateCount(double* out);
    int GetAndResetLostPacketCount();
    double GetLastMeasuredJitter();
    double GetLastMeasuredDelay();

private:
    struct jitter_packet_t
    {
        Buffer buffer = Buffer();
        double recvTimeDiff;
        std::size_t size;
        std::uint32_t timestamp;
        bool isEC;
    };

    enum class Status
    {
        OK = 1,
        MISSING,
        BUFFERING
    };

    static std::size_t CallbackIn(unsigned char* data, std::size_t len, void* param);
    static std::size_t CallbackOut(unsigned char* data, std::size_t len, void* param);
    void PutInternal(jitter_packet_t* pkt, bool overwriteExisting);
    Status GetInternal(jitter_packet_t* pkt, int offset, bool advance);
    void Advance();

    BufferPool<JITTER_SLOT_SIZE, JITTER_SLOT_COUNT> m_bufferPool;
    mutable Mutex m_mutex;
    jitter_packet_t m_slots[JITTER_SLOT_COUNT];
    std::int64_t m_nextTimestamp = 0;
    std::uint32_t m_step;
    std::atomic<double> m_minDelay{6};
    std::uint32_t m_minMinDelay;
    std::uint32_t m_maxMinDelay;
    std::uint32_t m_maxUsedSlots;
    std::uint32_t m_lastPutTimestamp;
    std::uint32_t m_lossesToReset;
    double m_resyncThreshold;
    unsigned int m_lostCount = 0;
    unsigned int m_lostSinceReset = 0;
    unsigned int m_gotSinceReset = 0;
    bool m_wasReset = true;
    bool m_needBuffering = true;
    HistoricBuffer<int, 64, double> m_delayHistory;
    HistoricBuffer<int, 64, double> m_lateHistory;
    bool m_adjustingDelay = false;
    unsigned int m_tickCount = 0;
    unsigned int m_latePacketCount = 0;
    unsigned int m_dontIncMinDelay = 0;
    unsigned int m_dontDecMinDelay = 0;
    int m_lostPackets = 0;
    double m_prevRecvTime = 0;
    double m_expectNextAtTime = 0;
    HistoricBuffer<double, 64> m_deviationHistory;
    double m_lastMeasuredJitter = 0;
    double m_lastMeasuredDelay = 0;
    int m_outstandingDelayChange = 0;
    unsigned int m_dontChangeDelay = 0;
    double m_avgDelay = 0;
    bool m_first = true;
#ifdef TGVOIP_DUMP_JITTER_STATS
    FILE* dump;
#endif
};

} // namespace tgvoip

#endif // LIBTGVOIP_JITTERBUFFER_H
