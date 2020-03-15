//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#include "CongestionControl.h"
#include "PrivateDefines.h"
#include "VoIPController.h"
#include "VoIPServerConfig.h"
#include "logging.h"
#include <cassert>
#include <limits>

using namespace tgvoip;

CongestionControl::CongestionControl()
    : m_tmpRtt(0)
    , m_tmpRttCount(0)
    , m_lossCount(0)
    , m_lastActionTime(0)
    , m_lastActionRtt(0)
    , m_stateTransitionTime(0)
    , m_lastSentSeq(0)
    , m_inflightDataSize(0)
    , m_cwnd(static_cast<std::size_t>(ServerConfig::GetSharedInstance()->GetInt("audio_congestion_window", 1024)))
{
    std::memset(m_inflightPackets, 0, sizeof(m_inflightPackets));
}

CongestionControl::~CongestionControl()
{
}

std::size_t CongestionControl::GetAcknowledgedDataSize() const
{
    return 0;
}

double CongestionControl::GetAverageRTT() const
{
    return m_rttHistory.NonZeroAverage();
}

std::size_t CongestionControl::GetInflightDataSize() const
{
    return m_inflightHistory.Average();
}

std::size_t CongestionControl::GetCongestionWindow() const
{
    return m_cwnd;
}

double CongestionControl::GetMinimumRTT() const
{
    return m_rttHistory.Min();
}

void CongestionControl::PacketAcknowledged(std::uint32_t seq)
{
    for (int i = 0; i < 100; ++i)
    {
        if (m_inflightPackets[i].seq == seq && m_inflightPackets[i].sendTime > 0)
        {
            m_tmpRtt += (VoIPController::GetCurrentTime() - m_inflightPackets[i].sendTime);
            m_tmpRttCount++;
            m_inflightPackets[i].sendTime = 0;
            m_inflightDataSize -= m_inflightPackets[i].size;
            break;
        }
    }
}

void CongestionControl::PacketSent(std::uint32_t seq, std::size_t size)
{
    if (!seqgt(seq, m_lastSentSeq) || seq == m_lastSentSeq)
    {
        LOGW("Duplicate outgoing seq %u", seq);
        return;
    }
    m_lastSentSeq = seq;
    double smallestSendTime = std::numeric_limits<double>::infinity();
    tgvoip_congestionctl_packet_t* slot = nullptr;
    int i;
    for (i = 0; i < 100; ++i)
    {
        if (m_inflightPackets[i].sendTime == 0)
        {
            slot = &m_inflightPackets[i];
            break;
        }
        if (smallestSendTime > m_inflightPackets[i].sendTime)
        {
            slot = &m_inflightPackets[i];
            smallestSendTime = slot->sendTime;
        }
    }
    assert(slot != nullptr);
    if (slot->sendTime > 0)
    {
        m_inflightDataSize -= slot->size;
        m_lossCount++;
        LOGD("Packet with seq %u was not acknowledged", slot->seq);
    }
    slot->seq = seq;
    slot->size = size;
    slot->sendTime = VoIPController::GetCurrentTime();
    m_inflightDataSize += size;
}

void CongestionControl::PacketLost(std::uint32_t seq)
{
    for (int i = 0; i < 100; ++i)
    {
        if (m_inflightPackets[i].seq == seq && m_inflightPackets[i].sendTime > 0)
        {
            m_inflightPackets[i].sendTime = 0;
            m_inflightDataSize -= m_inflightPackets[i].size;
            ++m_lossCount;
            break;
        }
    }
}

void CongestionControl::Tick()
{
    m_tickCount++;
    if (m_tmpRttCount > 0)
    {
        m_rttHistory.Add(m_tmpRtt / m_tmpRttCount);
        m_tmpRtt = 0;
        m_tmpRttCount = 0;
    }
    int i;
    for (i = 0; i < 100; i++)
    {
        if (m_inflightPackets[i].sendTime != 0 && VoIPController::GetCurrentTime() - m_inflightPackets[i].sendTime > 2)
        {
            m_inflightPackets[i].sendTime = 0;
            m_inflightDataSize -= m_inflightPackets[i].size;
            ++m_lossCount;
            LOGD("Packet with seq %u was not acknowledged", m_inflightPackets[i].seq);
        }
    }
    m_inflightHistory.Add(m_inflightDataSize);
}

ConctlAct CongestionControl::GetBandwidthControlAction() const
{
    if (VoIPController::GetCurrentTime() - m_lastActionTime < 1)
        return ConctlAct::NONE;
    std::size_t inflightAvg = GetInflightDataSize();
    std::size_t max = m_cwnd + m_cwnd / 10;
    std::size_t min = m_cwnd - m_cwnd / 10;
    if (inflightAvg < min)
    {
        m_lastActionTime = VoIPController::GetCurrentTime();
        return ConctlAct::INCREASE;
    }
    if (inflightAvg > max)
    {
        m_lastActionTime = VoIPController::GetCurrentTime();
        return ConctlAct::DECREASE;
    }
    return ConctlAct::NONE;
}

std::uint32_t CongestionControl::GetSendLossCount() const
{
    return m_lossCount;
}
