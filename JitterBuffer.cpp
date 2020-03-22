//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#include "JitterBuffer.h"
#include "VoIPController.h"
#include "VoIPServerConfig.h"
#include "logging.h"
#include <cmath>

using namespace tgvoip;

JitterBuffer::JitterBuffer(MediaStreamItf* out, std::uint32_t step)
{
    if (out != nullptr)
        out->SetCallback(JitterBuffer::CallbackOut, this);
    m_step = step;
    for (jitter_packet_t& slot : m_slots)
    {
        slot.buffer = Buffer();
        slot.recvTimeDiff = 0.0;
        slot.size = 0;
        slot.timestamp = 0;
        slot.isEC = false;
    }
    if (step < 30)
    {
        m_minMinDelay  = static_cast<std::uint32_t>(ServerConfig::GetSharedInstance()->GetInt("jitter_min_delay_20",  6));
        m_maxMinDelay  = static_cast<std::uint32_t>(ServerConfig::GetSharedInstance()->GetInt("jitter_max_delay_20", 25));
        m_maxUsedSlots = static_cast<std::uint32_t>(ServerConfig::GetSharedInstance()->GetInt("jitter_max_slots_20", 50));
    }
    else if (step < 50)
    {
        m_minMinDelay  = static_cast<std::uint32_t>(ServerConfig::GetSharedInstance()->GetInt("jitter_min_delay_40",  4));
        m_maxMinDelay  = static_cast<std::uint32_t>(ServerConfig::GetSharedInstance()->GetInt("jitter_max_delay_40", 15));
        m_maxUsedSlots = static_cast<std::uint32_t>(ServerConfig::GetSharedInstance()->GetInt("jitter_max_slots_40", 30));
    }
    else
    {
        m_minMinDelay  = static_cast<std::uint32_t>(ServerConfig::GetSharedInstance()->GetInt("jitter_min_delay_60",  2));
        m_maxMinDelay  = static_cast<std::uint32_t>(ServerConfig::GetSharedInstance()->GetInt("jitter_max_delay_60", 10));
        m_maxUsedSlots = static_cast<std::uint32_t>(ServerConfig::GetSharedInstance()->GetInt("jitter_max_slots_60", 20));
    }
    m_lossesToReset = static_cast<std::uint32_t>(ServerConfig::GetSharedInstance()->GetInt("jitter_losses_to_reset", 20));
    m_resyncThreshold = ServerConfig::GetSharedInstance()->GetDouble("jitter_resync_threshold", 1.0);
#ifdef TGVOIP_DUMP_JITTER_STATS
#ifdef TGVOIP_JITTER_DUMP_FILE
    dump = fopen(TGVOIP_JITTER_DUMP_FILE, "w");
#elif defined(__ANDROID__)
    dump = fopen("/sdcard/tgvoip_jitter_dump.txt", "w");
#else
    dump = fopen("tgvoip_jitter_dump.txt", "w");
#endif
    tgvoip_log_file_write_header(dump);
    fprintf(dump, "PTS\tRTS\tNumInBuf\tAJitter\tADelay\tTDelay\n");
#endif
    ResetNonBlocking();
}

JitterBuffer::~JitterBuffer()
{
    Reset();
}

void JitterBuffer::SetMinPacketCount(std::uint32_t count)
{
    LOGI("jitter: set min packet count %u", count);
    MutexGuard m(m_mutex);
    m_minDelay = count;
    m_minMinDelay = count;
    //Reset();
}

int JitterBuffer::GetMinPacketCount() const
{
    MutexGuard m(m_mutex);
    return JitterBuffer::GetMinPacketCountNonBlocking();
}

int JitterBuffer::GetMinPacketCountNonBlocking() const
{
    return static_cast<int>(m_minDelay);
}

std::size_t JitterBuffer::CallbackIn(std::uint8_t* data, std::size_t len, void* param)
{
    //((JitterBuffer*)param)->HandleInput(data, len);
    return 0;
}

std::size_t JitterBuffer::CallbackOut(std::uint8_t* data, std::size_t len, void* param)
{
    return 0; //((JitterBuffer*)param)->HandleOutput(data, len, 0, nullptr);
}

void JitterBuffer::HandleInput(std::uint8_t* data, std::size_t len, std::uint32_t timestamp, bool isEC)
{
    MutexGuard m(m_mutex);
    jitter_packet_t pkt;
    pkt.size = len;
    pkt.buffer = Buffer::Wrap(
        data, len, [](void*) {}, [](void* a, std::size_t) -> void* { return a; });
    pkt.timestamp = timestamp;
    pkt.isEC = isEC;
    PutInternal(&pkt, !isEC);
    //LOGV("in, ts=%d, ec=%d", timestamp, isEC);
}

void JitterBuffer::ResetNonBlocking()
{
    m_wasReset = true;
    m_needBuffering = true;
    m_lastPutTimestamp = 0;
    for (jitter_packet_t& slot : m_slots)
        if (!slot.buffer.IsEmpty())
            slot.buffer = Buffer();
    m_delayHistory.Reset();
    m_lateHistory.Reset();
    m_adjustingDelay = false;
    m_lostSinceReset = 0;
    m_gotSinceReset = 0;
    m_expectNextAtTime = 0;
    m_deviationHistory.Reset();
    m_outstandingDelayChange = 0;
    m_dontChangeDelay = 0;
}

void JitterBuffer::Reset()
{
    MutexGuard m(m_mutex);
    ResetNonBlocking();
}

std::size_t JitterBuffer::HandleOutput(std::uint8_t* buffer, std::size_t len, int offsetInSteps,
                                       bool advance, int& playbackScaledDuration, bool& isEC)
{
    jitter_packet_t pkt;
    pkt.buffer = Buffer::Wrap(
        buffer, len, [](void*) {}, [](void* a, std::size_t) -> void* { return a; });
    pkt.size = len;
    MutexGuard m(m_mutex);
    if (m_first)
    {
        m_first = false;
        unsigned int delay = GetCurrentDelayNonBlocking();
        if (delay > 5)
        {
            LOGW("jitter: delay too big upon start (%u), dropping packets", delay);
            while (static_cast<int>(delay) > GetMinPacketCountNonBlocking())
            {
                assert(GetMinPacketCountNonBlocking() >= 0);
                for (jitter_packet_t& slot : m_slots)
                {
                    if (slot.timestamp == m_nextTimestamp)
                    {
                        if (!slot.buffer.IsEmpty())
                        {
                            slot.buffer = Buffer();
                        }
                        break;
                    }
                }
                Advance();
                --delay;
            }
        }
    }
    Status result = GetInternal(&pkt, offsetInSteps, advance);
    if (m_outstandingDelayChange != 0)
    {
        if (m_outstandingDelayChange < 0)
        {
            playbackScaledDuration = 40;
            m_outstandingDelayChange += 20;
        }
        else
        {
            playbackScaledDuration = 80;
            m_outstandingDelayChange -= 20;
        }
        //LOGV("outstanding delay change: %d", outstandingDelayChange);
    }
    else if (advance && GetCurrentDelayNonBlocking() == 0)
    {
        //LOGV("stretching packet because the next one is late");
        playbackScaledDuration = 80;
    }
    else
    {
        playbackScaledDuration = 60;
    }
    if (result == Status::OK)
    {
        isEC = pkt.isEC;
        return pkt.size;
    }
    return 0;
}

JitterBuffer::Status JitterBuffer::GetInternal(jitter_packet_t* pkt, int offset, bool advance)
{
    /*if(needBuffering && lastPutTimestamp<nextTimestamp){
		LOGV("jitter: don't have timestamp %lld, buffering", (long long int)nextTimestamp);
		Advance();
        return Status::BUFFERING;
	}*/

    //needBuffering=false;

    std::int64_t timestampToGet = m_nextTimestamp + offset * static_cast<std::int64_t>(m_step);

    std::size_t i;
    for (i = 0; i < m_slots.size(); ++i)
    {
        if (!m_slots[i].buffer.IsEmpty() && m_slots[i].timestamp == timestampToGet)
        {
            break;
        }
    }

    if (i < m_slots.size())
    {
        if (pkt != nullptr && pkt->size < m_slots[i].size)
        {
            LOGE("jitter: packet won't fit into provided buffer of %d (need %d)", int(m_slots[i].size), int(pkt->size));
        }
        else
        {
            if (pkt != nullptr)
            {
                pkt->size = m_slots[i].size;
                pkt->timestamp = m_slots[i].timestamp;
                pkt->buffer.CopyFrom(m_slots[i].buffer, m_slots[i].size);
                pkt->isEC = m_slots[i].isEC;
            }
        }
        m_slots[i].buffer = Buffer();
        if (offset == 0)
            Advance();
        m_lostCount = 0;
        m_needBuffering = false;
        return Status::OK;
    }

    LOGV("jitter: found no packet for timestamp %lld (last put = %d, lost = %d)", static_cast<long long>(timestampToGet), m_lastPutTimestamp, m_lostCount);

    if (advance)
        Advance();

    if (!m_needBuffering)
    {
        ++m_lostCount;
        if (offset == 0)
        {
            ++m_lostPackets;
            ++m_lostSinceReset;
        }
        if (m_lostCount >= m_lossesToReset || (m_gotSinceReset > m_minDelay * 25 && m_lostSinceReset > m_gotSinceReset / 2))
        {
            LOGW("jitter: lost %d packets in a row, resetting", m_lostCount);
            //minDelay++;
            m_dontIncMinDelay = 16;
            m_dontDecMinDelay += 128;
            double currentDelay = static_cast<double>(GetCurrentDelayNonBlocking());
            if (currentDelay < m_minDelay)
                m_nextTimestamp -= static_cast<std::int64_t>(m_minDelay - currentDelay);
            m_lostCount = 0;
            ResetNonBlocking();
        }

        return Status::MISSING;
    }
    return Status::BUFFERING;
}

void JitterBuffer::PutInternal(jitter_packet_t* pkt, bool overwriteExisting)
{
    if (pkt->size > JITTER_SLOT_SIZE)
    {
        LOGE("The packet is too big to fit into the jitter buffer");
        return;
    }

    for (jitter_packet_t& slot : m_slots)
    {
        if (!slot.buffer.IsEmpty() && slot.timestamp == pkt->timestamp)
        {
            //LOGV("Found existing packet for timestamp %u, overwrite %d", pkt->timestamp, overwriteExisting);
            if (overwriteExisting)
            {
                slot.buffer.CopyFrom(pkt->buffer, pkt->size);
                slot.size = pkt->size;
                slot.isEC = pkt->isEC;
            }
            return;
        }
    }
    ++m_gotSinceReset;
    if (m_wasReset)
    {
        m_wasReset = false;
        m_outstandingDelayChange = 0;
        m_nextTimestamp = static_cast<std::int64_t>(pkt->timestamp - m_step * m_minDelay);
        m_first = true;
        LOGI("jitter: resyncing, next timestamp = %lld (step=%d, minDelay=%f)", static_cast<long long>(m_nextTimestamp), m_step, double(m_minDelay));
    }

    for (jitter_packet_t& slot : m_slots)
        if (slot.buffer.IsEmpty() && slot.timestamp < m_nextTimestamp - 1)
            slot.buffer = Buffer();

    /*double prevTime=0;
    std::uint32_t closestTime=0;
	for(i=0;i<JITTER_SLOT_COUNT;i++){
        if(m_slots[i].buffer!=nullptr && pkt->timestamp-m_slots[i].timestamp<pkt->timestamp-closestTime){
            closestTime=m_slots[i].timestamp;
            prevTime=m_slots[i].recvTime;
		}
	}*/
    double time = VoIPController::GetCurrentTime();
    if (m_expectNextAtTime != 0)
    {
        double dev = m_expectNextAtTime - time;
        //LOGV("packet dev %f", dev);
        m_deviationHistory.Add(dev);
        m_expectNextAtTime += m_step / 1000.0;
    }
    else
    {
        m_expectNextAtTime = time + m_step / 1000.0;
    }

    if (pkt->timestamp < m_nextTimestamp)
    {
        //LOGW("jitter: would drop packet with timestamp %d because it is late but not hopelessly", pkt->timestamp);
        ++m_latePacketCount;
        --m_lostPackets;
    }
    else if (pkt->timestamp < m_nextTimestamp - 1)
    {
        //LOGW("jitter: dropping packet with timestamp %d because it is too late", pkt->timestamp);
        ++m_latePacketCount;
        return;
    }

    if (pkt->timestamp > m_lastPutTimestamp)
        m_lastPutTimestamp = pkt->timestamp;

    {
        std::size_t i;
        for (i = 0; i < m_slots.size(); ++i)
            if (m_slots[i].buffer.IsEmpty())
                break;

        if (i == m_slots.size() || GetCurrentDelayNonBlocking() >= m_maxUsedSlots)
        {
            std::size_t toRemove = m_slots.size();
            std::uint32_t bestTimestamp = 0xFFFFFFFF;
            for (std::size_t i = 0; i < m_slots.size(); ++i)
            {
                if (!m_slots[i].buffer.IsEmpty() && m_slots[i].timestamp < bestTimestamp)
                {
                    toRemove = i;
                    bestTimestamp = m_slots[i].timestamp;
                }
            }
            Advance();
            m_slots[toRemove].buffer = Buffer();
            i = toRemove;
        }
        m_slots[i].timestamp = pkt->timestamp;
        m_slots[i].size = pkt->size;
        m_slots[i].buffer = m_bufferPool.Get();
        m_slots[i].recvTimeDiff = time - m_prevRecvTime;
        m_slots[i].isEC = pkt->isEC;
        m_slots[i].buffer.CopyFrom(pkt->buffer, pkt->size);
    }
#ifdef TGVOIP_DUMP_JITTER_STATS
    fprintf(dump, "%u\t%.03f\t%d\t%.03f\t%.03f\t%.03f\n", pkt->timestamp, time, GetCurrentDelay(), lastMeasuredJitter, lastMeasuredDelay, minDelay);
#endif
    m_prevRecvTime = time;
}

void JitterBuffer::Advance()
{
    m_nextTimestamp += m_step;
}

unsigned int JitterBuffer::GetCurrentDelay() const
{
    MutexGuard m(m_mutex);
    return GetCurrentDelayNonBlocking();
}

unsigned int JitterBuffer::GetCurrentDelayNonBlocking() const
{
    unsigned int delay = 0;
    for (const jitter_packet_t& slot : m_slots)
        if (!slot.buffer.IsEmpty())
            ++delay;
    return delay;
}

void JitterBuffer::Tick()
{
    MutexGuard m(m_mutex);

    m_lateHistory.Add(static_cast<int>(m_latePacketCount));
    m_latePacketCount = 0;
    bool absolutelyNoLatePackets = m_lateHistory.Max() == 0;

    double avgLate16 = m_lateHistory.Average(16);
    //LOGV("jitter: avg late=%.1f, %.1f, %.1f", avgLate16, avgLate32, avgLate64);
    if (avgLate16 >= m_resyncThreshold)
    {
        LOGV("resyncing: avgLate16=%f, resyncThreshold=%f", avgLate16, m_resyncThreshold);
        m_wasReset = true;
    }

    if (absolutelyNoLatePackets && m_dontDecMinDelay > 0)
        --m_dontDecMinDelay;

    m_delayHistory.Add(static_cast<int>(GetCurrentDelayNonBlocking()));
    m_avgDelay = m_delayHistory.Average(32);

    double stddev = 0;
    double avgdev = m_deviationHistory.Average();
    for (std::size_t i = 0; i < m_deviationHistory.Size(); ++i)
    {
        double d = (m_deviationHistory[i] - avgdev);
        stddev += d * d;
    }
    stddev = std::sqrt(stddev / 64);
    std::uint32_t stddevDelay = static_cast<std::uint32_t>(std::ceil(stddev * 2 * 1000 / m_step));
    if (stddevDelay < m_minMinDelay)
        stddevDelay = m_minMinDelay;
    if (stddevDelay > m_maxMinDelay)
        stddevDelay = m_maxMinDelay;
    if (stddevDelay != m_minDelay)
    {
        std::int32_t diff = static_cast<std::int32_t>(stddevDelay - m_minDelay);
        if (diff > 0)
            m_dontDecMinDelay = 100;
        if (diff < -1)
            diff = -1;
        if (diff > 1)
            diff = 1;
        if ((diff > 0 && m_dontIncMinDelay == 0) || (diff < 0 && m_dontDecMinDelay == 0))
        {
            //nextTimestamp+=diff*(std::int32_t)step;
            m_minDelay = m_minDelay + diff;
            m_outstandingDelayChange += diff * 60;
            m_dontChangeDelay += 32;
            //LOGD("new delay from stddev %f", minDelay);
            if (diff < 0)
                m_dontDecMinDelay += 25;
            if (diff > 0)
                m_dontIncMinDelay = 25;
        }
    }
    m_lastMeasuredJitter = stddev;
    m_lastMeasuredDelay = stddevDelay;
    //LOGV("stddev=%.3f, avg=%.3f, ndelay=%d, dontDec=%u", stddev, avgdev, stddevDelay, dontDecMinDelay);
    if (m_dontChangeDelay == 0)
    {
        if (m_avgDelay > m_minDelay + 0.5)
        {
            m_outstandingDelayChange -= m_avgDelay > m_minDelay + 2 ? 60 : 20;
            m_dontChangeDelay += 10;
        }
        else if (m_avgDelay < m_minDelay - 0.3)
        {
            m_outstandingDelayChange += 20;
            m_dontChangeDelay += 10;
        }
    }
    if (m_dontChangeDelay > 0)
        --m_dontChangeDelay;

    //LOGV("jitter: avg delay=%d, delay=%d, late16=%.1f, dontDecMinDelay=%d", avgDelay, delayHistory[0], avgLate16, dontDecMinDelay);
    /*if(!adjustingDelay) {
		if (((minDelay==1 ? (avgDelay>=3) : (avgDelay>=minDelay/2)) && delayHistory[0]>minDelay && avgLate16<=0.1 && absolutelyNoLatePackets && dontDecMinDelay<32 && min>minDelay)) {
			LOGI("jitter: need adjust");
			adjustingDelay=true;
		}
	}else{
		if(!absolutelyNoLatePackets){
			LOGI("jitter: done adjusting because we're losing packets");
			adjustingDelay=false;
		}else if(tickCount%5==0){
			LOGD("jitter: removing a packet to reduce delay");
			GetInternal(nullptr, 0);
			expectNextAtTime=0;
			if(GetCurrentDelay()<=minDelay || min<=minDelay){
				adjustingDelay = false;
				LOGI("jitter: done adjusting");
			}
		}
	}*/

    ++m_tickCount;
}

void JitterBuffer::GetAverageLateCount(double* out) const
{
    double avgLate64, avgLate32, avgLate16;
    {
        MutexGuard m(m_mutex);
        avgLate64 = m_lateHistory.Average();
        avgLate32 = m_lateHistory.Average(32);
        avgLate16 = m_lateHistory.Average(16);
    }
    out[0] = avgLate16;
    out[1] = avgLate32;
    out[2] = avgLate64;
}

int JitterBuffer::GetAndResetLostPacketCount()
{
    MutexGuard m(m_mutex);
    int r = m_lostPackets;
    m_lostPackets = 0;
    return r;
}

double JitterBuffer::GetLastMeasuredJitter() const
{
    MutexGuard m(m_mutex);
    return m_lastMeasuredJitter;
}

double JitterBuffer::GetLastMeasuredDelay() const
{
    MutexGuard m(m_mutex);
    return m_lastMeasuredDelay;
}

double JitterBuffer::GetAverageDelay() const
{
    MutexGuard m(m_mutex);
    return m_avgDelay;
}
