//
// Created by Grishka on 25/02/2019.
//

#ifndef LIBTGVOIP_SCREAMCONGESTIONCONTROLLER_H
#define LIBTGVOIP_SCREAMCONGESTIONCONTROLLER_H

#include "../Buffers.h"
#include <cstdint>
#include <vector>

namespace tgvoip
{

namespace video
{

class ScreamCongestionController
{
public:
    ScreamCongestionController();
    void AdjustBitrate();
    void ProcessAcks(float oneWayDelay, uint32_t m_bytesNewlyAcked, uint32_t lossCount, double rtt);
    void ProcessPacketSent(uint32_t size);
    void ProcessPacketLost(uint32_t size);
    double GetPacingInterval();
    void UpdateMediaRate(uint32_t frameSize);
    uint32_t GetBitrate();

private:
    void UpdateVariables(float qdelay);
    void UpdateCWnd(float qdelay);
    void AdjustQDelayTarget(float qdelay);
    void CalculateSendWindow(float qdelay);

    void UpdateBytesInFlightHistory();

    struct ValueSample
    {
        uint32_t sample;
        double time;
    };

    float m_qdelayTarget;
    float m_qdelayFractionAvg = 0.0f;
    HistoricBuffer<float, 20> m_qdelayFractionHist;
    float m_qdelayTrend = 0.0f;
    float m_qdelayTrendMem = 0.0f;
    HistoricBuffer<float, 100> m_qdelayNormHist;
    bool m_inFastIncrease = true;
    uint32_t m_cwnd;
    uint32_t m_bytesNewlyAcked = 0;
    uint32_t m_maxBytesInFlight = 0;
    uint32_t m_sendWnd = 0;
    uint32_t m_targetBitrate = 0;
    uint32_t m_targetBitrateLastMax = 1;
    float m_rateTransmit = 0.0f;
    float m_rateAck = 0.0f;
    float m_rateMedia = 0.0f;
    float m_rateMediaMedian = 0.0f;
    float m_sRTT = 0.0f;
    uint32_t m_rtpQueueSize = 0;
    uint32_t m_rtpSize = 1024; //0;
    float m_lossEventRate = 0.0f;

    bool m_lossPending = false;
    float m_prevOneWayDelay = 0.0f;
    double m_ignoreLossesUntil = 0.0;
    uint32_t m_prevLossCount = 0;
    double m_lastTimeQDelayTrendWasGreaterThanLo = 0.0;
    double m_lastVariablesUpdateTime = 0.0;
    double m_lastRateAdjustmentTime = 0.0;
    double m_lastCWndUpdateTime = 0.0;
    uint32_t m_bytesInFlight = 0;
    std::vector<ValueSample> m_bytesInFlightHistory;
    uint32_t m_bytesSent = 0;
    uint32_t m_bytesAcked = 0;
    uint32_t m_bytesMedia = 0;
    double m_rateTransmitUpdateTime = 0.0;
    double m_rateMediaUpdateTime = 0.0;
    HistoricBuffer<float, 25> m_rateMediaHistory;
};

} // namespace video

} // namespace tgvoip

#endif // LIBTGVOIP_SCREAMCONGESTIONCONTROLLER_H
