//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#ifndef _WIN32
#include <sys/time.h>
#include <unistd.h>
#endif
#include "Buffers.h"
#include "OpusDecoder.h"
#include "OpusEncoder.h"
#include "PacketSender.h"
#include "PrivateDefines.h"
#include "VoIPController.h"
#include "VoIPServerConfig.h"
#include "json11.hpp"
#include "logging.h"
#include "threading.h"
#include "video/VideoPacketSender.h"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <exception>
#include <cfloat>
#include <cinttypes>
#include <cmath>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <ctime>
#include <cwchar>
#if defined HAVE_CONFIG_H || defined TGVOIP_USE_INSTALLED_OPUS
#include <opus/opus.h>
#else
#include "opus.h"
#endif

inline int pad4(int x)
{
    int r = PAD4(x);
    if (r == 4)
        return 0;
    return r;
}

using namespace tgvoip;
// using namespace std; // Already used in BlockingQueue.h.

#ifdef __APPLE__
#include "os/darwin/AudioUnitIO.h"
#include <mach/mach_time.h>
double VoIPController::machTimebase = 0;
std::uint64_t VoIPController::machTimestart = 0;
#endif

#ifdef _WIN32
std::int64_t VoIPController::win32TimeScale = 0;
bool VoIPController::didInitWin32TimeScale = false;
#endif

#ifdef __ANDROID__
#include "NetworkSocket.h"
#include "os/android/AudioInputAndroid.h"
#include "os/android/JNIUtilities.h"

extern jclass jniUtilitiesClass;
#endif

#if defined(TGVOIP_USE_CALLBACK_AUDIO_IO)
#include "audio/AudioIOCallback.h"
#endif

#define ENFORCE_MSG_THREAD assert(m_messageThread.IsCurrent())

extern FILE* tgvoipLogFile;

IPv4Address::IPv4Address(std::string addr)
    : addr(std::move(addr))
{
}

IPv6Address::IPv6Address(std::string addr)
    : addr(std::move(addr))
{
}

#pragma mark - Public API

VoIPController::VoIPController()
    : m_state(State::WAIT_INIT)
    , m_networkType(NetType::UNKNOWN)
    , m_runReceiver(false)
    , m_seq(1)
    , m_lastRemoteSeq(0)
    , m_lastRemoteAckSeq(0)
    , m_lastSentSeq(0)
    , m_audioTimestampIn(0)
    , m_audioTimestampOut(0)
    , m_audioInput(nullptr)
    , m_audioOutput(nullptr)
    , m_encoder(nullptr)
    , m_echoCanceller(nullptr)
    , m_echoCancellationStrength(1)
    , m_stopping(false)
    , m_audioOutStarted(false)
    , m_recvThread(nullptr)
    , m_sendThread(nullptr)
    , m_packetsReceived(0)
    , m_recvLossCount(0)
    , m_prevSendLossCount(0)
    , m_waitingForAcks(false)
    , m_dontSendPackets(0)
    , m_micMuted(false)
    , m_waitingForRelayPeerInfo(false)
    , m_allowP2p(true)
    , m_dataSavingMode(false)
    , m_dataSavingRequestedByPeer(false)
    , m_activeNetItfName("")
    , m_publicEndpointsReqTime(0)
    , m_connectionInitTime(0)
    , m_lastRecvPacketTime(0)
    , m_peerVersion(0)
    , m_conctl(new CongestionControl())
    , m_receivedInit(false)
    , m_receivedInitAck(false)
    , m_udpSocket(NetworkSocket::Create(NetworkProtocol::UDP))
    , m_realUdpSocket(m_udpSocket)
    , m_stats
      ({
          .bytesSentWifi = 0,
          .bytesRecvdWifi = 0,
          .bytesSentMobile = 0,
          .bytesRecvdMobile = 0
      })
    , m_statsDump(nullptr)
    , m_currentAudioInput("default")
    , m_currentAudioOutput("default")
    , m_useTCP(false)
    , m_useUDP(true)
    , m_didAddTcpRelays(false)
    , m_selectCanceller(SocketSelectCanceller::Create())
    , m_udpConnectivityState(UdpState::UNKNOWN)
    , m_lastUdpPingTime(0)
    , m_udpPingCount(0)
    , m_proxyProtocol(Proxy::NONE)
    , m_proxyAddress("")
    , m_proxyPort(0)
    , m_proxyUsername("")
    , m_proxyPassword("")
    , m_peerCapabilities(0)
    , m_callbacks
      ({
        .connectionStateChanged = nullptr,
        .signalBarCountChanged = nullptr,
        .groupCallKeySent = nullptr,
        .groupCallKeyReceived = nullptr,
        .upgradeToGroupCallRequested = nullptr
      })
    , m_didReceiveGroupCallKey(false)
    , m_didReceiveGroupCallKeyAck(false)
    , m_didSendGroupCallKey(false)
    , m_didSendUpgradeRequest(false)
    , m_didInvokeUpgradeCallback(false)
    , m_connectionMaxLayer(0)
    , m_useMTProto2(false)
    , m_setCurrentEndpointToTCP(false)
    , m_useIPv6(false)
    , m_peerIPv6Available(false)
    , m_didAddIPv6Relays(false)
    , m_didSendIPv6Endpoint(false)
    , m_shittyInternetMode(false)
    , m_rawSendQueue(64)
{
    m_unsentStreamPackets.store(0);

    ServerConfig* serverConfigInstance = ServerConfig::GetSharedInstance();
    m_maxAudioBitrate        = static_cast<std::uint32_t>(serverConfigInstance->GetInt("audio_max_bitrate", 20000));
    m_maxAudioBitrateGPRS    = static_cast<std::uint32_t>(serverConfigInstance->GetInt("audio_max_bitrate_gprs", 8000));
    m_maxAudioBitrateEDGE    = static_cast<std::uint32_t>(serverConfigInstance->GetInt("audio_max_bitrate_edge", 16000));
    m_maxAudioBitrateSaving  = static_cast<std::uint32_t>(serverConfigInstance->GetInt("audio_max_bitrate_saving", 8000));
    m_initAudioBitrate       = static_cast<std::uint32_t>(serverConfigInstance->GetInt("audio_init_bitrate", 16000));
    m_initAudioBitrateGPRS   = static_cast<std::uint32_t>(serverConfigInstance->GetInt("audio_init_bitrate_gprs", 8000));
    m_initAudioBitrateEDGE   = static_cast<std::uint32_t>(serverConfigInstance->GetInt("audio_init_bitrate_edge", 8000));
    m_initAudioBitrateSaving = static_cast<std::uint32_t>(serverConfigInstance->GetInt("audio_init_bitrate_saving", 8000));
    m_audioBitrateStepIncr   = static_cast<std::uint32_t>(serverConfigInstance->GetInt("audio_bitrate_step_incr", 1000));
    m_audioBitrateStepDecr   = static_cast<std::uint32_t>(serverConfigInstance->GetInt("audio_bitrate_step_decr", 1000));
    m_minAudioBitrate        = static_cast<std::uint32_t>(serverConfigInstance->GetInt("audio_min_bitrate", 8000));
    m_needRateFlags          = static_cast<std::uint32_t>(serverConfigInstance->GetInt("rate_flags", std::int32_t{~0}));
    m_maxUnsentStreamPackets = static_cast<std::uint32_t>(serverConfigInstance->GetInt("max_unsent_stream_packets", 2));
    m_unackNopThreshold      = static_cast<std::uint32_t>(serverConfigInstance->GetInt("unack_nop_threshold", 10));
    m_relaySwitchThreshold                              = serverConfigInstance->GetDouble("relay_switch_threshold", 0.8);
    m_p2pToRelaySwitchThreshold                         = serverConfigInstance->GetDouble("p2p_to_relay_switch_threshold", 0.6);
    m_relayToP2pSwitchThreshold                         = serverConfigInstance->GetDouble("relay_to_p2p_switch_threshold", 0.8);
    m_reconnectingTimeout                               = serverConfigInstance->GetDouble("reconnecting_state_timeout", 2.0);
    m_rateMaxAcceptableRTT                              = serverConfigInstance->GetDouble("rate_min_rtt", 0.6);
    m_rateMaxAcceptableSendLoss                         = serverConfigInstance->GetDouble("rate_min_send_loss", 0.2);
    m_packetLossToEnableExtraEC                         = serverConfigInstance->GetDouble("packet_loss_for_extra_ec", 0.02);


#ifdef __APPLE__
    machTimestart = 0;
#endif

    std::shared_ptr<Stream> stm = std::make_shared<Stream>();
    stm->id = 1;
    stm->type = STREAM_TYPE_AUDIO;
    stm->codec = CODEC_OPUS;
    stm->enabled = 1;
    stm->frameDuration = 60;
    m_outgoingStreams.push_back(std::move(stm));
}

VoIPController::~VoIPController()
{
    LOGD("Entered VoIPController::~VoIPController");
    if (!m_stopping)
    {
        LOGE("!!!!!!!!!!!!!!!!!!!! CALL controller->Stop() BEFORE DELETING THE CONTROLLER OBJECT !!!!!!!!!!!!!!!!!!!!!!!1");
        abort();
    }
    LOGD("before close socket");
    if (m_udpSocket)
        delete m_udpSocket;
    if (m_udpSocket != m_realUdpSocket)
        delete m_realUdpSocket;
    LOGD("before delete audioIO");
    if (m_audioIO)
    {
        delete m_audioIO;
        m_audioInput = nullptr;
        m_audioOutput = nullptr;
    }
    for (std::vector<std::shared_ptr<Stream>>::iterator _stm = m_incomingStreams.begin(); _stm != m_incomingStreams.end(); ++_stm)
    {
        std::shared_ptr<Stream> stm = *_stm;
        LOGD("before stop decoder");
        if (stm->decoder)
        {
            stm->decoder->Stop();
        }
    }
    LOGD("before delete encoder");
    if (m_encoder)
    {
        m_encoder->Stop();
        delete m_encoder;
    }
    LOGD("before delete echo canceller");
    if (m_echoCanceller)
    {
        m_echoCanceller->Stop();
        delete m_echoCanceller;
    }
    delete m_conctl;
    if (m_statsDump)
        fclose(m_statsDump);
    delete m_selectCanceller;
    LOGD("Left VoIPController::~VoIPController");
    if (tgvoipLogFile)
    {
        FILE* log = tgvoipLogFile;
        tgvoipLogFile = nullptr;
        fclose(log);
    }
#if defined(TGVOIP_USE_CALLBACK_AUDIO_IO)
    if (m_preprocDecoder)
    {
        opus_decoder_destroy(m_preprocDecoder);
        m_preprocDecoder = nullptr;
    }
#endif
}

VoIPController::Config::Config(double initTimeout, double recvTimeout, DataSaving dataSaving,
                               bool enableAEC, bool enableNS, bool enableAGC, bool enableCallUpgrade)
    : initTimeout(initTimeout)
    , recvTimeout(recvTimeout)
    , dataSaving(dataSaving)
    , enableAEC(enableAEC)
    , enableNS(enableNS)
    , enableAGC(enableAGC)
    , enableCallUpgrade(enableCallUpgrade)
{
}

VoIPController::PendingOutgoingPacket::PendingOutgoingPacket(std::uint32_t seq, PktType type, std::size_t len, Buffer&& data, std::int64_t endpoint)
    : seq(seq)
    , type(type)
    , len(len)
    , data(std::move(data))
    , endpoint(endpoint)
{
}

VoIPController::PendingOutgoingPacket::PendingOutgoingPacket(PendingOutgoingPacket&& other)
    : seq(other.seq)
    , type(other.type)
    , len(other.len)
    , data(std::move(other.data))
    , endpoint(other.endpoint)
{

}

VoIPController::PendingOutgoingPacket& VoIPController::PendingOutgoingPacket::operator=(PendingOutgoingPacket&& other)
{
    if (this != &other)
    {
        seq = other.seq;
        type = other.type;
        len = other.len;
        data = std::move(other.data);
        endpoint = other.endpoint;
    }
    return *this;
}

void VoIPController::Stop()
{
    LOGD("Entered VoIPController::Stop");
    m_stopping = true;
    m_runReceiver = false;
    LOGD("before shutdown socket");
    if (m_udpSocket)
        m_udpSocket->Close();
    if (m_realUdpSocket != m_udpSocket)
        m_realUdpSocket->Close();
    m_selectCanceller->CancelSelect();
    //Buffer emptyBuf(0);
    //PendingOutgoingPacket emptyPacket{0, 0, 0, move(emptyBuf), 0};
    //sendQueue->Put(move(emptyPacket));
    m_rawSendQueue.Put(RawPendingOutgoingPacket{ .packet = NetworkPacket::Empty(), .socket = nullptr });
    LOGD("before join sendThread");
    if (m_sendThread)
    {
        m_sendThread->Join();
        delete m_sendThread;
    }
    LOGD("before join recvThread");
    if (m_recvThread)
    {
        m_recvThread->Join();
        delete m_recvThread;
    }
    LOGD("before stop messageThread");
    m_messageThread.Stop();
    {
        LOGD("Before stop audio I/O");
        MutexGuard m(m_audioIOMutex);
        if (m_audioInput)
        {
            m_audioInput->Stop();
            m_audioInput->SetCallback(nullptr, nullptr);
        }
        if (m_audioOutput)
        {
            m_audioOutput->Stop();
            m_audioOutput->SetCallback(nullptr, nullptr);
        }
    }
    if (m_videoPacketSender)
    {
        LOGD("before delete video packet sender");
        delete m_videoPacketSender;
        m_videoPacketSender = nullptr;
    }
    LOGD("Left VoIPController::Stop [need rate = %d]", m_needRate);
}

bool VoIPController::NeedRate()
{
    return m_needRate && ServerConfig::GetSharedInstance()->GetBoolean("bad_call_rating", false);
}

void VoIPController::SetRemoteEndpoints(std::vector<Endpoint> endpoints, bool allowP2p, std::int32_t connectionMaxLayer)
{
    LOGW("Set remote endpoints, allowP2P=%d, connectionMaxLayer=%u", allowP2p ? 1 : 0, connectionMaxLayer);
    assert(!m_runReceiver);
    m_preferredRelay = 0;

    this->m_endpoints.clear();
    m_didAddTcpRelays = false;
    m_useTCP = true;
    for (std::vector<Endpoint>::iterator itrtr = endpoints.begin(); itrtr != endpoints.end(); ++itrtr)
    {
        if (this->m_endpoints.find(itrtr->id) != this->m_endpoints.end())
            LOGE("Endpoint IDs are not unique!");
        this->m_endpoints[itrtr->id] = *itrtr;
        if (m_currentEndpoint == 0)
            m_currentEndpoint = itrtr->id;
        if (itrtr->type == Endpoint::Type::TCP_RELAY)
            m_didAddTcpRelays = true;
        if (itrtr->type == Endpoint::Type::UDP_RELAY)
            m_useTCP = false;
        LOGV("Adding endpoint: %s:%d, %s", itrtr->address.ToString().c_str(), itrtr->port, itrtr->type == Endpoint::Type::UDP_RELAY ? "UDP" : "TCP");
    }
    m_preferredRelay = m_currentEndpoint;
    this->m_allowP2p = allowP2p;
    this->m_connectionMaxLayer = connectionMaxLayer;
    if (connectionMaxLayer >= 74)
    {
        m_useMTProto2 = true;
    }
    AddIPv6Relays();
}

void VoIPController::Start()
{
    LOGW("Starting voip controller");
    m_udpSocket->Open();
    if (m_udpSocket->IsFailed())
    {
        SetState(State::FAILED);
        return;
    }

    m_runReceiver = true;
    m_recvThread = new Thread(std::bind(&VoIPController::RunRecvThread, this));
    m_recvThread->SetName("VoipRecv");
    m_recvThread->Start();

    m_messageThread.Start();
}

void VoIPController::Connect()
{
    assert(m_state != State::WAIT_INIT_ACK);
    m_connectionInitTime = GetCurrentTime();
    if (m_config.initTimeout == 0.0)
    {
        LOGE("Init timeout is 0 -- did you forget to set config?");
        m_config.initTimeout = 30.0;
    }

    //InitializeTimers();
    //SendInit();
    m_sendThread = new Thread(std::bind(&VoIPController::RunSendThread, this));
    m_sendThread->SetName("VoipSend");
    m_sendThread->Start();
}

void VoIPController::SetEncryptionKey(char* key, bool isOutgoing)
{
    std::memcpy(m_encryptionKey, key, 256);
    std::uint8_t sha1[SHA1_LENGTH];
    crypto.sha1(reinterpret_cast<std::uint8_t*>(m_encryptionKey), 256, sha1);
    std::memcpy(m_keyFingerprint, sha1 + (SHA1_LENGTH - 8), 8);
    std::uint8_t sha256[SHA256_LENGTH];
    crypto.sha256(reinterpret_cast<std::uint8_t*>(m_encryptionKey), 256, sha256);
    std::memcpy(m_callID, sha256 + (SHA256_LENGTH - 16), 16);
    this->m_isOutgoing = isOutgoing;
}

void VoIPController::SetNetworkType(NetType type)
{
    m_networkType = type;
    UpdateDataSavingState();
    UpdateAudioBitrateLimit();
    m_myIPv6 = NetworkAddress::Empty();
    std::string itfName = m_udpSocket->GetLocalInterfaceInfo(nullptr, &m_myIPv6);
    LOGI("set network type: %s, active interface %s", NetworkTypeToString(type).c_str(), itfName.c_str());
    LOGI("Local IPv6 address: %s", m_myIPv6.ToString().c_str());
    if (IS_MOBILE_NETWORK(m_networkType))
    {
        CellularCarrierInfo carrier = GetCarrierInfo();
        if (!carrier.name.empty())
        {
            LOGI("Carrier: %s [%s; mcc=%s, mnc=%s]", carrier.name.c_str(), carrier.countryCode.c_str(), carrier.mcc.c_str(), carrier.mnc.c_str());
        }
    }
    if (itfName != m_activeNetItfName)
    {
        m_udpSocket->OnActiveInterfaceChanged();
        LOGI("Active network interface changed: %s -> %s", m_activeNetItfName.c_str(), itfName.c_str());
        bool isFirstChange = m_activeNetItfName.length() == 0 && m_state != State::ESTABLISHED && m_state != State::RECONNECTING;
        m_activeNetItfName = itfName;
        if (isFirstChange)
            return;
        m_messageThread.Post([this] {
            m_wasNetworkHandover = true;
            if (m_currentEndpoint)
            {
                const Endpoint& _currentEndpoint = m_endpoints.at(m_currentEndpoint);
                const Endpoint& _preferredRelay = m_endpoints.at(m_preferredRelay);
                if (_currentEndpoint.type != Endpoint::Type::UDP_RELAY)
                {
                    if (_preferredRelay.type == Endpoint::Type::UDP_RELAY)
                        m_currentEndpoint = m_preferredRelay;
                    MutexGuard m(m_endpointsMutex);
                    constexpr std::int64_t lanID = static_cast<std::int64_t>(FOURCC('L', 'A', 'N', '4')) << 32;
                    m_endpoints.erase(lanID);
                    for (std::pair<const std::int64_t, Endpoint>& e : m_endpoints)
                    {
                        Endpoint& endpoint = e.second;
                        if (endpoint.type == Endpoint::Type::UDP_RELAY && m_useTCP)
                        {
                            m_useTCP = false;
                            if (_preferredRelay.type == Endpoint::Type::TCP_RELAY)
                            {
                                m_preferredRelay = m_currentEndpoint = endpoint.id;
                            }
                        }
                        else if (endpoint.type == Endpoint::Type::TCP_RELAY && endpoint.m_socket)
                        {
                            endpoint.m_socket->Close();
                            //delete endpoint.socket;
                            //endpoint.socket=nullptr;
                        }
                        //if(endpoint->type==Endpoint::Type::UDP_P2P_INET){
                        endpoint.m_averageRTT = 0;
                        endpoint.m_rtts.Reset();
                        //}
                    }
                }
            }
            m_lastUdpPingTime = 0;
            if (m_proxyProtocol == Proxy::SOCKS5)
                InitUDPProxy();
            if (m_allowP2p && m_currentEndpoint)
            {
                SendPublicEndpointsRequest();
            }
            BufferOutputStream s(4);
            s.WriteInt32(m_dataSavingMode ? INIT_FLAG_DATA_SAVING_ENABLED : 0);
            if (m_peerVersion < 6)
            {
                SendPacketReliably(PktType::NETWORK_CHANGED, s.GetBuffer(), s.GetLength(), 1, 20);
            }
            else
            {
                Buffer buf(std::move(s));
                SendExtra(buf, EXTRA_TYPE_NETWORK_CHANGED);
            }
            m_needReInitUdpProxy = true;
            m_selectCanceller->CancelSelect();
            m_didSendIPv6Endpoint = false;

            AddIPv6Relays();
            ResetUdpAvailability();
            ResetEndpointPingStats();
        });
    }
}

double VoIPController::GetAverageRTT()
{
    ENFORCE_MSG_THREAD;

    if (m_lastSentSeq >= m_lastRemoteAckSeq)
    {
        std::uint32_t diff = m_lastSentSeq - m_lastRemoteAckSeq;
        //LOGV("rtt diff=%u", diff);
        if (diff < 32)
        {
            double res = 0;
            int count = 0;
            for (std::vector<RecentOutgoingPacket>::iterator itr = m_recentOutgoingPackets.begin(); itr != m_recentOutgoingPackets.end(); ++itr)
            {
                if (itr->ackTime > 0)
                {
                    res += (itr->ackTime - itr->sendTime);
                    count++;
                }
            }
            if (count > 0)
                res /= count;
            return res;
        }
    }
    return 999;
}

void VoIPController::SetMicMute(bool mute)
{
    if (m_micMuted == mute)
        return;
    m_micMuted = mute;
    if (m_audioInput)
    {
        if (mute)
            m_audioInput->Stop();
        else
            m_audioInput->Start();
        if (!m_audioInput->IsInitialized())
        {
            m_lastError = Error::AUDIO_IO;
            SetState(State::FAILED);
            return;
        }
    }
    if (m_echoCanceller)
        m_echoCanceller->Enable(!mute);
    if (m_state == State::ESTABLISHED)
    {
        m_messageThread.Post([this] {
            for (std::shared_ptr<Stream>& s : m_outgoingStreams)
            {
                if (s->type == STREAM_TYPE_AUDIO)
                {
                    s->enabled = !m_micMuted;
                    if (m_peerVersion < 6)
                    {
                        std::uint8_t buf[2];
                        buf[0] = s->id;
                        buf[1] = (m_micMuted ? 0 : 1);
                        SendPacketReliably(PktType::STREAM_STATE, buf, 2, 0.5, 20);
                    }
                    else
                    {
                        SendStreamFlags(*s);
                    }
                }
            }
        });
    }
}

std::string VoIPController::GetDebugString()
{
    std::string r = "Remote endpoints: \n";
    char buffer[2048];
    MutexGuard m(m_endpointsMutex);
    for (std::pair<const std::int64_t, Endpoint>& _e : m_endpoints)
    {
        Endpoint& endpoint = _e.second;
        const char* type;
        switch (endpoint.type)
        {
        case Endpoint::Type::UDP_P2P_INET:
            type = "UDP_P2P_INET";
            break;
        case Endpoint::Type::UDP_P2P_LAN:
            type = "UDP_P2P_LAN";
            break;
        case Endpoint::Type::UDP_RELAY:
            type = "UDP_RELAY";
            break;
        case Endpoint::Type::TCP_RELAY:
            type = "TCP_RELAY";
            break;
        default:
            type = "UNKNOWN";
            break;
        }
        snprintf(buffer, sizeof(buffer), "%s:%u %dms %d 0x%" PRIx64 " [%s%s]\n", endpoint.address.IsEmpty() ? ("[" + endpoint.v6address.ToString() + "]").c_str() : endpoint.address.ToString().c_str(), endpoint.port, (int)(endpoint.m_averageRTT * 1000), endpoint.m_udpPongCount, (std::uint64_t)endpoint.id, type, m_currentEndpoint == endpoint.id ? ", IN_USE" : "");
        r += buffer;
    }
    if (m_shittyInternetMode)
    {
        snprintf(buffer, sizeof(buffer), "ShittyInternetMode: level %d\n", m_extraEcLevel);
        r += buffer;
    }
    double avgLate[3];
    std::shared_ptr<Stream> stm = GetStreamByType(STREAM_TYPE_AUDIO, false);
    std::shared_ptr<JitterBuffer> jitterBuffer;
    if (stm)
        jitterBuffer = stm->jitterBuffer;
    if (jitterBuffer)
        jitterBuffer->GetAverageLateCount(avgLate);
    else
        std::memset(avgLate, 0, 3 * sizeof(double));
    snprintf(
        buffer,
        sizeof(buffer),
        "Jitter buffer: %d/%.2f | %.1f, %.1f, %.1f\n"
        "RTT avg/min: %d/%d\n"
        "Congestion window: %d/%d bytes\n"
        "Key fingerprint: %02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%s\n"
        "Last sent/ack'd seq: %u/%u\n"
        "Last recvd seq: %u\n"
        "Send/recv losses: %u/%u (%d%%)\n"
        "Audio bitrate: %d kbit\n"
        "Outgoing queue: %u\n"
        //					 "Packet grouping: %d\n"
        "Frame size out/in: %d/%d\n"
        "Bytes sent/recvd: %llu/%llu",
        jitterBuffer ? jitterBuffer->GetMinPacketCount() : 0,
        jitterBuffer ? jitterBuffer->GetAverageDelay() : 0,
        avgLate[0],
        avgLate[1],
        avgLate[2],
        // (int)(GetAverageRTT()*1000), 0,
        static_cast<int>(m_conctl->GetAverageRTT() * 1000),
        static_cast<int>(m_conctl->GetMinimumRTT() * 1000),
        static_cast<int>(m_conctl->GetInflightDataSize()),
        static_cast<int>(m_conctl->GetCongestionWindow()),
        m_keyFingerprint[0],
        m_keyFingerprint[1],
        m_keyFingerprint[2],
        m_keyFingerprint[3],
        m_keyFingerprint[4],
        m_keyFingerprint[5],
        m_keyFingerprint[6],
        m_keyFingerprint[7],
        m_useMTProto2 ? " (MTProto2.0)" : "",
        m_lastSentSeq,
        m_lastRemoteAckSeq,
        m_lastRemoteSeq,
        m_sendLosses,
        m_recvLossCount,
        m_encoder ? m_encoder->GetPacketLoss() : 0,
        m_encoder ? (m_encoder->GetBitrate() / 1000) : 0,
        m_unsentStreamPackets.load(),
        //			 audioPacketGrouping,
        m_outgoingStreams[0]->frameDuration, m_incomingStreams.size() > 0 ? m_incomingStreams[0]->frameDuration : 0,
        static_cast<unsigned long long>(m_stats.bytesSentMobile + m_stats.bytesSentWifi),
        static_cast<unsigned long long>(m_stats.bytesRecvdMobile + m_stats.bytesRecvdWifi)
    );
    r += buffer;

    if (m_config.enableVideoSend)
    {
        std::shared_ptr<Stream> vstm = GetStreamByType(STREAM_TYPE_VIDEO, true);
        if (vstm && vstm->enabled && m_videoPacketSender)
        {
            snprintf(buffer, sizeof(buffer), "\nVideo out: %ux%u '%c%c%c%c' %u kbit", vstm->width, vstm->height, PRINT_FOURCC(vstm->codec), m_videoPacketSender->GetBitrate());
            r += buffer;
        }
    }
    if (!m_peerVideoDecoders.empty())
    {
        r += "\nPeer codecs: ";
        for (std::uint32_t codec : m_peerVideoDecoders)
        {
            snprintf(buffer, sizeof(buffer), "'%c%c%c%c' ", PRINT_FOURCC(codec));
            r += buffer;
        }
    }
    if (m_config.enableVideoReceive)
    {
        std::shared_ptr<Stream> vstm = GetStreamByType(STREAM_TYPE_VIDEO, false);
        if (vstm && vstm->enabled)
        {
            snprintf(buffer, sizeof(buffer), "\nVideo in: %ux%u '%c%c%c%c'", vstm->width, vstm->height, PRINT_FOURCC(vstm->codec));
            r += buffer;
        }
    }

    return r;
}

const char* VoIPController::GetVersion()
{
    return LIBTGVOIP_VERSION;
}

std::int64_t VoIPController::GetPreferredRelayID()
{
    return m_preferredRelay;
}

Error VoIPController::GetLastError()
{
    return m_lastError;
}

void VoIPController::GetStats(TrafficStats* stats)
{
    std::memcpy(stats, &this->m_stats, sizeof(TrafficStats));
}

std::string VoIPController::GetDebugLog()
{
    std::map<std::string, json11::Json> network {
        {"type", NetworkTypeToString(m_networkType)}};
    if (IS_MOBILE_NETWORK(m_networkType))
    {
        CellularCarrierInfo carrier = GetCarrierInfo();
        if (!carrier.name.empty())
        {
            network["carrier"] = carrier.name;
            network["country"] = carrier.countryCode;
            network["mcc"] = carrier.mcc;
            network["mnc"] = carrier.mnc;
        }
    }
    else if (m_networkType == NetType::WIFI)
    {
#ifdef __ANDROID__
        jni::DoWithJNI([&](JNIEnv* env) {
            jmethodID getWifiInfoMethod = env->GetStaticMethodID(jniUtilitiesClass, "getWifiInfo", "()[I");
            jintArray res = static_cast<jintArray>(env->CallStaticObjectMethod(jniUtilitiesClass, getWifiInfoMethod));
            if (res)
            {
                jint* wifiInfo = env->GetIntArrayElements(res, nullptr);
                network["rssi"] = wifiInfo[0];
                network["link_speed"] = wifiInfo[1];
                env->ReleaseIntArrayElements(res, wifiInfo, JNI_ABORT);
            }
        });
#endif
    }
    /*vector<json11::Json> lpkts;
	for(DebugLoggedPacket& lpkt:debugLoggedPackets){
		lpkts.push_back(json11::Json::array{lpkt.timestamp, lpkt.seq, lpkt.length});
	}
	return json11::Json(json11::Json::object{
			{"log_type", "out_packet_stats"},
			{"libtgvoip_version", LIBTGVOIP_VERSION},
			{"network", network},
			{"protocol_version", std::min(peerVersion, PROTOCOL_VERSION)},
			{"total_losses", json11::Json::object{
                    {"s", (std::int32_t)conctl->GetSendLossCount()},
                    {"r", (std::int32_t)recvLossCount}
			}},
			{"call_duration", GetCurrentTime()-connectionInitTime},
			{"out_packet_stats", lpkts}
	}).dump();*/

    std::vector<json11::Json> _endpoints;
    for (std::pair<const std::int64_t, Endpoint>& _e : m_endpoints)
    {
        Endpoint& e = _e.second;
        std::string type;
        std::map<std::string, json11::Json> je
        {
            { "rtt", static_cast<int>(e.m_averageRTT * 1000) }
        };
        std::int64_t id = 0;
        if (e.type == Endpoint::Type::UDP_RELAY)
        {
            je["type"] = e.IsIPv6Only() ? "udp_relay6" : "udp_relay";
            id = e.CleanID();
            if (e.m_totalUdpPings == 0)
                je["udp_pings"] = 0.0;
            else
                je["udp_pings"] = static_cast<double>(e.m_totalUdpPingReplies) / e.m_totalUdpPings;
            je["self_rtt"] = static_cast<int>(e.m_selfRtts.Average() * 1000);
        }
        else if (e.type == Endpoint::Type::TCP_RELAY)
        {
            je["type"] = e.IsIPv6Only() ? "tcp_relay6" : "tcp_relay";
            id = e.CleanID();
        }
        else if (e.type == Endpoint::Type::UDP_P2P_INET)
        {
            je["type"] = e.IsIPv6Only() ? "p2p_inet6" : "p2p_inet";
        }
        else if (e.type == Endpoint::Type::UDP_P2P_LAN)
        {
            je["type"] = "p2p_lan";
        }
        if (m_preferredRelay == e.id && m_wasEstablished)
            je["pref"] = true;
        if (id)
        {
            std::ostringstream s;
            s << id;
            je["id"] = s.str();
        }
        _endpoints.push_back(je);
    }

    std::string p2pType = "none";
    Endpoint& cur = m_endpoints[m_currentEndpoint];
    if (cur.type == Endpoint::Type::UDP_P2P_INET)
        p2pType = cur.IsIPv6Only() ? "inet6" : "inet";
    else if (cur.type == Endpoint::Type::UDP_P2P_LAN)
        p2pType = "lan";

    std::vector<std::string> problems;
    if (m_lastError == Error::TIMEOUT)
        problems.push_back("timeout");
    if (m_wasReconnecting)
        problems.push_back("reconnecting");
    if (m_wasExtraEC)
        problems.push_back("extra_ec");
    if (m_wasEncoderLaggy)
        problems.push_back("encoder_lag");
    if (!m_wasEstablished)
        problems.push_back("not_inited");
    if (m_wasNetworkHandover)
        problems.push_back("network_handover");

    return json11::Json(json11::Json::object
    {
        { "log_type", "call_stats" },
        { "libtgvoip_version", LIBTGVOIP_VERSION },
        { "network", network },
        { "protocol_version", std::min(m_peerVersion, PROTOCOL_VERSION) },
        { "udp_avail", m_udpConnectivityState == UdpState::AVAILABLE },
        { "tcp_used", m_useTCP },
        { "p2p_type", p2pType },
        { "packet_stats",
          json11::Json::object
          {
              { "out", static_cast<int>(m_seq) },
              { "in", static_cast<int>(m_packetsReceived) },
              { "lost_out", static_cast<int>(m_conctl->GetSendLossCount()) },
              { "lost_in", static_cast<int>(m_recvLossCount) }
          }
        },
        { "endpoints", _endpoints },
        { "problems", problems }
    }).dump();
}

std::vector<AudioInputDevice> VoIPController::EnumerateAudioInputs()
{
    std::vector<AudioInputDevice> devs;
    audio::AudioInput::EnumerateDevices(devs);
    return devs;
}

std::vector<AudioOutputDevice> VoIPController::EnumerateAudioOutputs()
{
    std::vector<AudioOutputDevice> devs;
    audio::AudioOutput::EnumerateDevices(devs);
    return devs;
}

void VoIPController::SetCurrentAudioInput(std::string id)
{
    m_currentAudioInput = id;
    if (m_audioInput)
        m_audioInput->SetCurrentDevice(id);
}

void VoIPController::SetCurrentAudioOutput(std::string id)
{
    m_currentAudioOutput = id;
    if (m_audioOutput)
        m_audioOutput->SetCurrentDevice(id);
}

std::string VoIPController::GetCurrentAudioInputID()
{
    return m_currentAudioInput;
}

std::string VoIPController::GetCurrentAudioOutputID()
{
    return m_currentAudioOutput;
}

void VoIPController::SetProxy(Proxy protocol, std::string address, std::uint16_t port, std::string username, std::string password)
{
    m_proxyProtocol = protocol;
    m_proxyAddress = std::move(address);
    m_proxyPort = port;
    m_proxyUsername = std::move(username);
    m_proxyPassword = std::move(password);
}

int VoIPController::GetSignalBarsCount()
{
    return m_signalBarsHistory.NonZeroAverage();
}

void VoIPController::SetCallbacks(VoIPController::Callbacks callbacks)
{
    this->m_callbacks = callbacks;
    if (callbacks.connectionStateChanged)
        callbacks.connectionStateChanged(this, m_state);
}

float VoIPController::GetOutputLevel() const
{
    return 0.0f;
}

void VoIPController::SetAudioOutputGainControlEnabled(bool enabled)
{
    LOGD("New output AGC state: %d", enabled);
}

std::uint32_t VoIPController::GetPeerCapabilities()
{
    return m_peerCapabilities;
}

void VoIPController::SendGroupCallKey(std::uint8_t* key)
{
    Buffer buf(256);
    buf.CopyFrom(key, 0, 256);
    std::shared_ptr<Buffer> keyPtr = std::make_shared<Buffer>(std::move(buf));
    m_messageThread.Post([this, keyPtr] {
        if (!(m_peerCapabilities & TGVOIP_PEER_CAP_GROUP_CALLS))
        {
            LOGE("Tried to send group call key but peer isn't capable of them");
            return;
        }
        if (m_didSendGroupCallKey)
        {
            LOGE("Tried to send a group call key repeatedly");
            return;
        }
        if (!m_isOutgoing)
        {
            LOGE("You aren't supposed to send group call key in an incoming call, use VoIPController::RequestCallUpgrade() instead");
            return;
        }
        m_didSendGroupCallKey = true;
        SendExtra(*keyPtr, EXTRA_TYPE_GROUP_CALL_KEY);
    });
}

void VoIPController::RequestCallUpgrade()
{
    m_messageThread.Post([this] {
        if (!(m_peerCapabilities & TGVOIP_PEER_CAP_GROUP_CALLS))
        {
            LOGE("Tried to send group call key but peer isn't capable of them");
            return;
        }
        if (m_didSendUpgradeRequest)
        {
            LOGE("Tried to send upgrade request repeatedly");
            return;
        }
        if (m_isOutgoing)
        {
            LOGE("You aren't supposed to send an upgrade request in an outgoing call, generate an encryption key and use VoIPController::SendGroupCallKey instead");
            return;
        }
        m_didSendUpgradeRequest = true;
        Buffer empty(0);
        SendExtra(empty, EXTRA_TYPE_REQUEST_GROUP);
    });
}

void VoIPController::SetEchoCancellationStrength(int strength)
{
    m_echoCancellationStrength = strength;
    if (m_echoCanceller)
        m_echoCanceller->SetAECStrength(strength);
}

#if defined(TGVOIP_USE_CALLBACK_AUDIO_IO)
void VoIPController::SetAudioDataCallbacks(std::function<void(std::int16_t*, std::size_t)> input, std::function<void(std::int16_t*, std::size_t)> output, std::function<void(std::int16_t*, std::size_t)> preproc = nullptr)
{
    m_audioInputDataCallback = input;
    m_audioOutputDataCallback = output;
    m_audioPreprocDataCallback = preproc;
    m_preprocDecoder = m_preprocDecoder ? m_preprocDecoder : opus_decoder_create(48000, 1, nullptr);
}
#endif

State VoIPController::GetConnectionState() const
{
    return m_state;
}

void VoIPController::SetConfig(const Config& cfg)
{
    m_config = cfg;
    if (tgvoipLogFile)
    {
        fclose(tgvoipLogFile);
        tgvoipLogFile = nullptr;
    }
    if (!m_config.logFilePath.empty())
    {
#ifndef _WIN32
        tgvoipLogFile = fopen(m_config.logFilePath.c_str(), "a");
#else
        if (_wfopen_s(&tgvoipLogFile, config.logFilePath.c_str(), L"a") != 0)
        {
            tgvoipLogFile = nullptr;
        }
#endif
        tgvoip_log_file_write_header(tgvoipLogFile);
    }
    else
    {
        tgvoipLogFile = nullptr;
    }
    if (m_statsDump)
    {
        fclose(m_statsDump);
        m_statsDump = nullptr;
    }
    if (!m_config.statsDumpFilePath.empty())
    {
#ifndef _WIN32
        m_statsDump = fopen(m_config.statsDumpFilePath.c_str(), "w");
#else
        if (_wfopen_s(&statsDump, config.statsDumpFilePath.c_str(), L"w") != 0)
        {
            statsDump = nullptr;
        }
#endif
        if (m_statsDump)
            fprintf(m_statsDump, "Time\tRTT\tLRSeq\tLSSeq\tLASeq\tLostR\tLostS\tCWnd\tBitrate\tLoss%%\tJitter\tJDelay\tAJDelay\n");
        //else
        //	LOGW("Failed to open stats dump file %s for writing", config.statsDumpFilePath.c_str());
    }
    else
    {
        m_statsDump = nullptr;
    }
    UpdateDataSavingState();
    UpdateAudioBitrateLimit();
}

void VoIPController::SetPersistentState(const std::vector<std::uint8_t>& state)
{
    using namespace json11;

    if (state.empty())
        return;
    std::string jsonErr;
    std::string json = std::string(state.begin(), state.end());
    Json _obj = Json::parse(json, jsonErr);
    if (!jsonErr.empty())
    {
        LOGE("Error parsing persistable state: %s", jsonErr.c_str());
        return;
    }
    Json::object obj = _obj.object_items();
    if (obj.find("proxy") != obj.end())
    {
        Json::object proxy = obj["proxy"].object_items();
        m_lastTestedProxyServer = proxy["server"].string_value();
        m_proxySupportsUDP = proxy["udp"].bool_value();
        m_proxySupportsTCP = proxy["tcp"].bool_value();
    }
}

std::vector<std::uint8_t> VoIPController::GetPersistentState()
{
    using namespace json11;

    Json::object obj = Json::object {
        {"ver", 1},
    };
    if (m_proxyProtocol == Proxy::SOCKS5)
    {
        char pbuf[128];
        snprintf(pbuf, sizeof(pbuf), "%s:%u", m_proxyAddress.c_str(), m_proxyPort);
        obj.insert({"proxy", Json::object {{"server", std::string(pbuf)}, {"udp", m_proxySupportsUDP}, {"tcp", m_proxySupportsTCP}}});
    }
    std::string _jstr = Json(obj).dump();
    const char* jstr = _jstr.c_str();
    return std::vector<std::uint8_t>(jstr, jstr + strlen(jstr));
}

void VoIPController::SetOutputVolume(float level)
{
    m_outputVolume.SetLevel(level);
}

void VoIPController::SetInputVolume(float level)
{
    m_inputVolume.SetLevel(level);
}

#if defined(__APPLE__) && TARGET_OS_OSX
void VoIPController::SetAudioOutputDuckingEnabled(bool enabled)
{
    macAudioDuckingEnabled = enabled;
    audio::AudioUnitIO* osxAudio = dynamic_cast<audio::AudioUnitIO*>(audioIO);
    if (osxAudio)
    {
        osxAudio->SetDuckingEnabled(enabled);
    }
}
#endif

#pragma mark - Internal intialization

void VoIPController::InitializeTimers()
{
    m_initTimeoutID = m_messageThread.Post([this] {
        LOGW("Init timeout, disconnecting");
        m_lastError = Error::TIMEOUT;
        SetState(State::FAILED);
    },
        m_config.initTimeout);

    if (!m_config.statsDumpFilePath.empty())
    {
        m_messageThread.Post([this] {
            if (m_statsDump && m_incomingStreams.size() == 1)
            {
                std::shared_ptr<JitterBuffer>& jitterBuffer = m_incomingStreams[0]->jitterBuffer;
                //fprintf(statsDump, "Time\tRTT\tLISeq\tLASeq\tCWnd\tBitrate\tJitter\tJDelay\tAJDelay\n");
                fprintf(m_statsDump, "%.3f\t%.3f\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%.3f\t%.3f\t%.3f\n",
                    GetCurrentTime() - m_connectionInitTime,
                    m_endpoints.at(m_currentEndpoint).m_rtts[0],
                    m_lastRemoteSeq,
                    (std::uint32_t)m_seq,
                    m_lastRemoteAckSeq,
                    m_recvLossCount,
                    m_conctl ? m_conctl->GetSendLossCount() : 0,
                    m_conctl ? static_cast<int>(m_conctl->GetInflightDataSize()) : 0,
                    m_encoder ? m_encoder->GetBitrate() : 0,
                    m_encoder ? m_encoder->GetPacketLoss() : 0,
                    jitterBuffer ? jitterBuffer->GetLastMeasuredJitter() : 0,
                    jitterBuffer ? jitterBuffer->GetLastMeasuredDelay() * 0.06 : 0,
                    jitterBuffer ? jitterBuffer->GetAverageDelay() * 0.06 : 0);
            }
        },
            0.1, 0.1);
    }

    m_messageThread.Post(std::bind(&VoIPController::SendRelayPings, this), 0.0, 2.0);
}

void VoIPController::RunSendThread()
{
    InitializeAudio();
    InitializeTimers();
    m_messageThread.Post(std::bind(&VoIPController::SendInit, this));

    while (true)
    {
        RawPendingOutgoingPacket pkt = m_rawSendQueue.GetBlocking();
        if (pkt.packet.IsEmpty())
            break;

        if (IS_MOBILE_NETWORK(m_networkType))
            m_stats.bytesSentMobile += (std::uint64_t)pkt.packet.data.Length();
        else
            m_stats.bytesSentWifi += (std::uint64_t)pkt.packet.data.Length();
        if (pkt.packet.protocol == NetworkProtocol::TCP)
        {
            if (pkt.socket && !pkt.socket->IsFailed())
            {
                pkt.socket->Send(std::move(pkt.packet));
            }
        }
        else
        {
            m_udpSocket->Send(std::move(pkt.packet));
        }
    }

    LOGI("=== send thread exiting ===");
}

#pragma mark - Miscellaneous

void VoIPController::SetState(State state)
{
    this->m_state = state;
    LOGV("Call state changed to %d", static_cast<int>(state));
    m_stateChangeTime = GetCurrentTime();
    m_messageThread.Post([this, state] {
        if (m_callbacks.connectionStateChanged)
            m_callbacks.connectionStateChanged(this, state);
    });
    if (state == State::ESTABLISHED)
    {
        SetMicMute(m_micMuted);
        if (!m_wasEstablished)
        {
            m_wasEstablished = true;
            m_messageThread.Post(std::bind(&VoIPController::UpdateRTT, this), 0.1, 0.5);
            m_messageThread.Post(std::bind(&VoIPController::UpdateAudioBitrate, this), 0.0, 0.3);
            m_messageThread.Post(std::bind(&VoIPController::UpdateCongestion, this), 0.0, 1.0);
            m_messageThread.Post(std::bind(&VoIPController::UpdateSignalBars, this), 1.0, 1.0);
            m_messageThread.Post(std::bind(&VoIPController::TickJitterBufferAndCongestionControl, this), 0.0, 0.1);
        }
    }
}

void VoIPController::SendStreamFlags(Stream& stream)
{
    ENFORCE_MSG_THREAD;

    BufferOutputStream s(5);
    s.WriteUInt8(stream.id);
    std::int32_t flags = 0;
    if (stream.enabled)
        flags |= STREAM_FLAG_ENABLED;
    if (stream.extraECEnabled)
        flags |= STREAM_FLAG_EXTRA_EC;
    if (stream.paused)
        flags |= STREAM_FLAG_PAUSED;
    s.WriteInt32(flags);
    LOGV("My stream state: id %u flags %u", stream.id, flags);
    Buffer buf(std::move(s));
    SendExtra(buf, EXTRA_TYPE_STREAM_FLAGS);
}

std::shared_ptr<VoIPController::Stream> VoIPController::GetStreamByType(int type, bool outgoing)
{
    std::shared_ptr<Stream> s;
    for (std::shared_ptr<Stream>& ss : (outgoing ? m_outgoingStreams : m_incomingStreams))
    {
        if (ss->type == type)
            return ss;
    }
    return s;
}

std::shared_ptr<VoIPController::Stream> VoIPController::GetStreamByID(std::uint8_t id, bool outgoing)
{
    std::shared_ptr<Stream> s;
    for (std::shared_ptr<Stream>& ss : (outgoing ? m_outgoingStreams : m_incomingStreams))
    {
        if (ss->id == id)
            return ss;
    }
    return s;
}

CellularCarrierInfo VoIPController::GetCarrierInfo()
{
#if defined(__APPLE__) && TARGET_OS_IOS
    return DarwinSpecific::GetCarrierInfo();
#elif defined(__ANDROID__)
    CellularCarrierInfo carrier;
    jni::DoWithJNI([&carrier](JNIEnv* env) {
        jmethodID getCarrierInfoMethod = env->GetStaticMethodID(jniUtilitiesClass, "getCarrierInfo", "()[Ljava/lang/String;");
        jobjectArray jinfo = (jobjectArray)env->CallStaticObjectMethod(jniUtilitiesClass, getCarrierInfoMethod);
        if (jinfo && env->GetArrayLength(jinfo) == 4)
        {
            carrier.name = jni::JavaStringToStdString(env, (jstring)env->GetObjectArrayElement(jinfo, 0));
            carrier.countryCode = jni::JavaStringToStdString(env, (jstring)env->GetObjectArrayElement(jinfo, 1));
            carrier.mcc = jni::JavaStringToStdString(env, (jstring)env->GetObjectArrayElement(jinfo, 2));
            carrier.mnc = jni::JavaStringToStdString(env, (jstring)env->GetObjectArrayElement(jinfo, 3));
        }
        else
        {
            LOGW("Failed to get carrier info");
        }
    });
    return carrier;
#else
    return CellularCarrierInfo();
#endif
}

#pragma mark - Audio I/O

void VoIPController::HandleAudioInput(std::uint8_t* data, std::size_t len, std::uint8_t* secondaryData, std::size_t secondaryLen)
{
    if (m_stopping)
        return;

    // TODO make an AudioPacketSender

    Buffer dataBuf = m_outgoingAudioBufferPool.Get();
    Buffer secondaryDataBuf = secondaryLen && secondaryData ? m_outgoingAudioBufferPool.Get() : Buffer();
    dataBuf.CopyFrom(data, 0, len);
    if (secondaryLen && secondaryData)
    {
        secondaryDataBuf.CopyFrom(secondaryData, 0, secondaryLen);
    }
    std::shared_ptr<Buffer> dataBufPtr = std::make_shared<Buffer>(std::move(dataBuf));
    std::shared_ptr<Buffer> secondaryDataBufPtr = std::make_shared<Buffer>(std::move(secondaryDataBuf));

    m_messageThread.Post([this, dataBufPtr, secondaryDataBufPtr, len, secondaryLen]() {
        m_unsentStreamPacketsHistory.Add(static_cast<unsigned int>(m_unsentStreamPackets));
        if (m_unsentStreamPacketsHistory.Average() >= m_maxUnsentStreamPackets && !m_videoPacketSender)
        {
            LOGW("Resetting stalled send queue");
            m_sendQueue.clear();
            m_unsentStreamPacketsHistory.Reset();
            m_unsentStreamPackets = 0;
        }
        if (m_waitingForAcks || m_dontSendPackets > 0 || (m_unsentStreamPackets >= m_maxUnsentStreamPackets /*&& endpoints[currentEndpoint].type==Endpoint::Type::TCP_RELAY*/))
        {
            LOGV("waiting for queue, dropping outgoing audio packet, %d %d %d [%d]", m_unsentStreamPackets.load(), m_waitingForAcks, m_dontSendPackets, m_maxUnsentStreamPackets);
            return;
        }
        //LOGV("Audio packet size %u", (unsigned int)len);
        if (!m_receivedInitAck)
            return;

        BufferOutputStream pkt(1500);

        bool hasExtraFEC = m_peerVersion >= 7 && secondaryLen && m_shittyInternetMode;
        std::uint8_t flags = static_cast<std::uint8_t>((len > 255 || hasExtraFEC) ? STREAM_DATA_FLAG_LEN16 : 0);
        pkt.WriteUInt8(1 | flags); // streamID + flags
        //pkt.WriteByte(flags);
        if (len > 255 || hasExtraFEC)
        {
            std::int16_t lenAndFlags = static_cast<std::int16_t>(len);
            if (hasExtraFEC)
                lenAndFlags |= STREAM_DATA_XFLAG_EXTRA_FEC;
            pkt.WriteInt16(lenAndFlags);
        }
        else
        {
            pkt.WriteUInt8(static_cast<std::uint8_t>(len));
        }
        pkt.WriteUInt32(m_audioTimestampOut);
        pkt.WriteBytes(*dataBufPtr, 0, len);

        if (hasExtraFEC)
        {
            pkt.WriteUInt8(static_cast<std::uint8_t>(std::min(static_cast<int>(m_ecAudioPackets.size()), m_extraEcLevel)));
            for (std::vector<Buffer>::iterator ecData = m_ecAudioPackets.begin() + std::max(0, static_cast<int>(m_ecAudioPackets.size()) - m_extraEcLevel);
                 ecData != m_ecAudioPackets.end(); ++ecData)
            {
                pkt.WriteUInt8(static_cast<std::uint8_t>(ecData->Length()));
                pkt.WriteBytes(*ecData);
            }
            Buffer ecBuf(secondaryLen);
            ecBuf.CopyFrom(**secondaryDataBufPtr, 0, secondaryLen);
            m_ecAudioPackets.push_back(std::move(ecBuf));
            while (m_ecAudioPackets.size() > 4)
                m_ecAudioPackets.erase(m_ecAudioPackets.begin());
        }

        ++m_unsentStreamPackets;
        std::size_t pktLength = pkt.GetLength();
        PendingOutgoingPacket p
        {
            /*.seq=*/GenerateOutSeq(),
            /*.type=*/PktType::STREAM_DATA,
            /*.len=*/pktLength,
            /*.data=*/Buffer(std::move(pkt)),
            /*.endpoint=*/0,
        };

        m_conctl->PacketSent(p.seq, p.len);

        SendOrEnqueuePacket(std::move(p));
        if (m_peerVersion < 7 && secondaryLen && m_shittyInternetMode)
        {
            Buffer ecBuf(secondaryLen);
            ecBuf.CopyFrom(*secondaryDataBufPtr, 0, secondaryLen);
            m_ecAudioPackets.push_back(std::move(ecBuf));
            while (m_ecAudioPackets.size() > 4)
                m_ecAudioPackets.erase(m_ecAudioPackets.begin());
            pkt = BufferOutputStream(1500);
            pkt.WriteUInt8(m_outgoingStreams[0]->id);
            pkt.WriteUInt32(m_audioTimestampOut);
            pkt.WriteUInt8(static_cast<std::uint8_t>(std::min(static_cast<int>(m_ecAudioPackets.size()), m_extraEcLevel)));
            for (std::vector<Buffer>::iterator ecData = m_ecAudioPackets.begin() + std::max(0, static_cast<int>(m_ecAudioPackets.size()) - m_extraEcLevel);
                 ecData != m_ecAudioPackets.end(); ++ecData)
            {
                pkt.WriteUInt8(static_cast<std::uint8_t>(ecData->Length()));
                pkt.WriteBytes(*ecData);
            }

            std::size_t pktLength = pkt.GetLength();
            PendingOutgoingPacket p
            {
                GenerateOutSeq(),
                PktType::STREAM_EC,
                pktLength,
                Buffer(std::move(pkt)),
                0
            };
            SendOrEnqueuePacket(std::move(p));
        }

        m_audioTimestampOut += m_outgoingStreams[0]->frameDuration;
    });

#if defined(TGVOIP_USE_CALLBACK_AUDIO_IO)
    if (m_audioPreprocDataCallback && m_preprocDecoder)
    {
        int size = opus_decode(m_preprocDecoder, data, len, m_preprocBuffer, 4096, 0);
        m_audioPreprocDataCallback(m_preprocBuffer, size);
    }
#endif
}

void VoIPController::InitializeAudio()
{
    double t = GetCurrentTime();
    std::shared_ptr<Stream> outgoingAudioStream = GetStreamByType(STREAM_TYPE_AUDIO, true);
    LOGI("before create audio io");
    m_audioIO = audio::AudioIO::Create(m_currentAudioInput, m_currentAudioOutput);
    m_audioInput = m_audioIO->GetInput();
    m_audioOutput = m_audioIO->GetOutput();
#ifdef __ANDROID__
    audio::AudioInputAndroid* androidInput = dynamic_cast<audio::AudioInputAndroid*>(audioInput);
    if (androidInput)
    {
        unsigned int effects = androidInput->GetEnabledEffects();
        if (!(effects & audio::AudioInputAndroid::EFFECT_AEC))
        {
            config.enableAEC = true;
            LOGI("Forcing software AEC because built-in is not good");
        }
        if (!(effects & audio::AudioInputAndroid::EFFECT_NS))
        {
            config.enableNS = true;
            LOGI("Forcing software NS because built-in is not good");
        }
    }
#elif defined(__APPLE__) && TARGET_OS_OSX
    SetAudioOutputDuckingEnabled(macAudioDuckingEnabled);
#endif
    LOGI("AEC: %d NS: %d AGC: %d", m_config.enableAEC, m_config.enableNS, m_config.enableAGC);
    m_echoCanceller = new EchoCanceller(m_config.enableAEC, m_config.enableNS, m_config.enableAGC);
    m_encoder = new OpusEncoder(m_audioInput, true);
    m_encoder->SetCallback(bind(&VoIPController::HandleAudioInput, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
    m_encoder->SetOutputFrameDuration(outgoingAudioStream->frameDuration);
    m_encoder->SetEchoCanceller(m_echoCanceller);
    m_encoder->SetSecondaryEncoderEnabled(false);
    if (m_config.enableVolumeControl)
    {
        m_encoder->AddAudioEffect(&m_inputVolume);
    }

#if defined(TGVOIP_USE_CALLBACK_AUDIO_IO)
    dynamic_cast<audio::AudioInputCallback*>(m_audioInput)->SetDataCallback(m_audioInputDataCallback);
    dynamic_cast<audio::AudioOutputCallback*>(m_audioOutput)->SetDataCallback(m_audioOutputDataCallback);
#endif

    if (!m_audioOutput->IsInitialized())
    {
        LOGE("Error initializing audio playback");
        m_lastError = Error::AUDIO_IO;

        SetState(State::FAILED);
        return;
    }
    UpdateAudioBitrateLimit();
    LOGI("Audio initialization took %f seconds", GetCurrentTime() - t);
}

void VoIPController::StartAudio()
{
    OnAudioOutputReady();

    m_encoder->Start();
    if (!m_micMuted)
    {
        m_audioInput->Start();
        if (!m_audioInput->IsInitialized())
        {
            LOGE("Error initializing audio capture");
            m_lastError = Error::AUDIO_IO;

            SetState(State::FAILED);
            return;
        }
    }
}

void VoIPController::OnAudioOutputReady()
{
    LOGI("Audio I/O ready");
    std::shared_ptr<Stream>& stm = m_incomingStreams[0];
    stm->decoder = std::make_shared<OpusDecoder>(m_audioOutput, true, m_peerVersion >= 6);
    stm->decoder->SetEchoCanceller(m_echoCanceller);
    if (m_config.enableVolumeControl)
    {
        stm->decoder->AddAudioEffect(&m_outputVolume);
    }
    stm->decoder->SetJitterBuffer(stm->jitterBuffer);
    stm->decoder->SetFrameDuration(stm->frameDuration);
    stm->decoder->Start();
}

void VoIPController::UpdateAudioOutputState()
{
    bool areAnyAudioStreamsEnabled = false;
    for (std::vector<std::shared_ptr<Stream>>::iterator s = m_incomingStreams.begin(); s != m_incomingStreams.end(); ++s)
    {
        if ((*s)->type == STREAM_TYPE_AUDIO && (*s)->enabled)
            areAnyAudioStreamsEnabled = true;
    }
    if (m_audioOutput)
    {
        LOGV("New audio output state: %d", areAnyAudioStreamsEnabled);
        if (m_audioOutput->IsPlaying() != areAnyAudioStreamsEnabled)
        {
            if (areAnyAudioStreamsEnabled)
                m_audioOutput->Start();
            else
                m_audioOutput->Stop();
        }
    }
}

#pragma mark - Bandwidth management

void VoIPController::UpdateAudioBitrateLimit()
{
    if (m_encoder)
    {
        if (m_dataSavingMode || m_dataSavingRequestedByPeer)
        {
            m_maxBitrate = m_maxAudioBitrateSaving;
            m_encoder->SetBitrate(m_initAudioBitrateSaving);
        }
        else if (m_networkType == NetType::GPRS)
        {
            m_maxBitrate = m_maxAudioBitrateGPRS;
            m_encoder->SetBitrate(m_initAudioBitrateGPRS);
        }
        else if (m_networkType == NetType::EDGE)
        {
            m_maxBitrate = m_maxAudioBitrateEDGE;
            m_encoder->SetBitrate(m_initAudioBitrateEDGE);
        }
        else
        {
            m_maxBitrate = m_maxAudioBitrate;
            m_encoder->SetBitrate(m_initAudioBitrate);
        }
        m_encoder->SetVadMode(m_dataSavingMode || m_dataSavingRequestedByPeer);
        if (m_echoCanceller)
            m_echoCanceller->SetVoiceDetectionEnabled(m_dataSavingMode || m_dataSavingRequestedByPeer);
    }
}

void VoIPController::UpdateDataSavingState()
{
    if (m_config.dataSaving == DataSaving::ALWAYS)
    {
        m_dataSavingMode = true;
    }
    else if (m_config.dataSaving == DataSaving::MOBILE)
    {
        m_dataSavingMode = m_networkType == NetType::GPRS || m_networkType == NetType::EDGE || m_networkType == NetType::THREE_G || m_networkType == NetType::HSPA || m_networkType == NetType::LTE || m_networkType == NetType::OTHER_MOBILE;
    }
    else
    {
        m_dataSavingMode = false;
    }
    LOGI("update data saving mode, config %d, enabled %d, reqd by peer %d", static_cast<int>(m_config.dataSaving), m_dataSavingMode, m_dataSavingRequestedByPeer);
}

#pragma mark - Networking & crypto

std::uint32_t VoIPController::GenerateOutSeq()
{
    return m_seq++;
}

void VoIPController::WritePacketHeader(std::uint32_t pseq, BufferOutputStream* s, PktType type, std::uint32_t length, PacketSender* source)
{
    std::uint32_t acks = 0;
    for (int i = 0; i < 32; ++i)
    {
        if (std::find(m_recentIncomingPackets.begin(), m_recentIncomingPackets.end(), m_lastRemoteSeq - static_cast<std::uint32_t>(i + 1)) != m_recentIncomingPackets.end())
        {
            acks |= (1 << (31 - i));
        }
    }

    if (m_peerVersion >= 8 || (!m_peerVersion && m_connectionMaxLayer >= 92))
    {
        s->WriteUInt8(static_cast<std::uint8_t>(type));
        s->WriteUInt32(m_lastRemoteSeq);
        s->WriteUInt32(pseq);
        s->WriteUInt32(acks);
        std::uint8_t flags;
        if (m_currentExtras.empty())
        {
            flags = 0;
        }
        else
        {
            flags = XPFLAG_HAS_EXTRA;
        }

        std::shared_ptr<Stream> videoStream = GetStreamByType(STREAM_TYPE_VIDEO, false);
        if (m_peerVersion >= 9 && videoStream && videoStream->enabled)
            flags |= XPFLAG_HAS_RECV_TS;

        s->WriteUInt8(flags);

        if (!m_currentExtras.empty())
        {
            s->WriteUInt8(static_cast<std::uint8_t>(m_currentExtras.size()));
            for (std::vector<UnacknowledgedExtraData>::iterator x = m_currentExtras.begin(); x != m_currentExtras.end(); ++x)
            {
                LOGV("Writing extra into header: type %u, length %d", x->type, static_cast<int>(x->data.Length()));
                assert(x->data.Length() <= 254);
                s->WriteUInt8(static_cast<std::uint8_t>(x->data.Length() + 1));
                s->WriteUInt8(x->type);
                s->WriteBytes(*x->data, x->data.Length());
                if (x->firstContainingSeq == 0)
                    x->firstContainingSeq = pseq;
            }
        }
        if (m_peerVersion >= 9 && videoStream && videoStream->enabled)
        {
            s->WriteUInt32(static_cast<std::uint32_t>((m_lastRecvPacketTime - m_connectionInitTime) * 1000));
        }
    }
    else
    {
        if (m_state == State::WAIT_INIT || m_state == State::WAIT_INIT_ACK)
        {
            s->WriteUInt32(TLID_DECRYPTED_AUDIO_BLOCK);
            std::int64_t randomID;
            crypto.rand_bytes(reinterpret_cast<std::uint8_t*>(&randomID), 8);
            s->WriteInt64(randomID);
            std::uint8_t randBytes[7];
            crypto.rand_bytes(randBytes, 7);
            s->WriteUInt8(7);
            s->WriteBytes(randBytes, 7);
            std::uint32_t pflags = PFLAG_HAS_RECENT_RECV | PFLAG_HAS_SEQ;
            if (length > 0)
            {
                pflags |= PFLAG_HAS_DATA;
            }
            if (m_state == State::WAIT_INIT || m_state == State::WAIT_INIT_ACK)
            {
                pflags |= PFLAG_HAS_CALL_ID | PFLAG_HAS_PROTO;
            }
            pflags |= (static_cast<std::uint32_t>(type)) << 24;
            s->WriteUInt32(pflags);

            if (pflags & PFLAG_HAS_CALL_ID)
            {
                s->WriteBytes(m_callID, 16);
            }
            s->WriteUInt32(m_lastRemoteSeq);
            s->WriteUInt32(pseq);
            s->WriteUInt32(acks);
            if (pflags & PFLAG_HAS_PROTO)
            {
                s->WriteInt32(PROTOCOL_NAME);
            }
            if (length > 0)
            {
                if (length <= 253)
                {
                    s->WriteUInt8(static_cast<std::uint8_t>(length));
                }
                else
                {
                    s->WriteUInt8(254);
                    s->WriteUInt8(static_cast<std::uint8_t>((length >>  0) & 0xFF));
                    s->WriteUInt8(static_cast<std::uint8_t>((length >>  8) & 0xFF));
                    s->WriteUInt8(static_cast<std::uint8_t>((length >> 16) & 0xFF));
                }
            }
        }
        else
        {
            s->WriteUInt32(TLID_SIMPLE_AUDIO_BLOCK);
            std::int64_t randomID;
            crypto.rand_bytes(reinterpret_cast<std::uint8_t*>(&randomID), 8);
            s->WriteInt64(randomID);
            std::uint8_t randBytes[7];
            crypto.rand_bytes(randBytes, 7);
            s->WriteUInt8(7);
            s->WriteBytes(randBytes, 7);
            std::uint32_t lenWithHeader = length + 13;
            if (lenWithHeader > 0)
            {
                if (lenWithHeader <= 253)
                {
                    s->WriteUInt8(static_cast<std::uint8_t>(lenWithHeader));
                }
                else
                {
                    s->WriteUInt8(std::uint8_t{254});
                    s->WriteUInt8(static_cast<std::uint8_t>((lenWithHeader >>  0) & 0xFF));
                    s->WriteUInt8(static_cast<std::uint8_t>((lenWithHeader >>  8) & 0xFF));
                    s->WriteUInt8(static_cast<std::uint8_t>((lenWithHeader >> 16) & 0xFF));
                }
            }
            s->WriteUInt8(static_cast<std::uint8_t>(type));
            s->WriteUInt32(m_lastRemoteSeq);
            s->WriteUInt32(pseq);
            s->WriteUInt32(acks);
            if (m_peerVersion >= 6)
            {
                if (m_currentExtras.empty())
                {
                    s->WriteUInt8(0);
                }
                else
                {
                    s->WriteUInt8(XPFLAG_HAS_EXTRA);
                    s->WriteUInt8(static_cast<std::uint8_t>(m_currentExtras.size()));
                    for (std::vector<UnacknowledgedExtraData>::iterator x = m_currentExtras.begin(); x != m_currentExtras.end(); ++x)
                    {
                        LOGV("Writing extra into header: type %u, length %d", x->type, static_cast<int>(x->data.Length()));
                        assert(x->data.Length() <= 254);
                        s->WriteUInt8(static_cast<std::uint8_t>(x->data.Length() + 1));
                        s->WriteUInt8(x->type);
                        s->WriteBytes(*x->data, x->data.Length());
                        if (x->firstContainingSeq == 0)
                            x->firstContainingSeq = pseq;
                    }
                }
            }
        }
    }

    m_unacknowledgedIncomingPacketCount = 0;
    m_recentOutgoingPackets.push_back(RecentOutgoingPacket
    {
        pseq,
        0,
        GetCurrentTime(),
        0,
        type,
        length,
        source,
        false
    });
    while (m_recentOutgoingPackets.size() > MAX_RECENT_PACKETS)
    {
        m_recentOutgoingPackets.erase(m_recentOutgoingPackets.begin());
    }
    m_lastSentSeq = pseq;
    //LOGI("packet header size %d", s->GetLength());
}

void VoIPController::SendInit()
{
    ENFORCE_MSG_THREAD;

    std::uint32_t initSeq = GenerateOutSeq();
    for (std::pair<const std::int64_t, Endpoint>& _e : m_endpoints)
    {
        Endpoint& e = _e.second;
        if (e.type == Endpoint::Type::TCP_RELAY && !m_useTCP)
            continue;
        BufferOutputStream out(1024);
        out.WriteInt32(PROTOCOL_VERSION);
        out.WriteInt32(MIN_PROTOCOL_VERSION);
        std::uint32_t flags = 0;
        if (m_config.enableCallUpgrade)
            flags |= INIT_FLAG_GROUP_CALLS_SUPPORTED;
        if (m_config.enableVideoReceive)
            flags |= INIT_FLAG_VIDEO_RECV_SUPPORTED;
        if (m_config.enableVideoSend)
            flags |= INIT_FLAG_VIDEO_SEND_SUPPORTED;
        if (m_dataSavingMode)
            flags |= INIT_FLAG_DATA_SAVING_ENABLED;
        out.WriteUInt32(flags);
        if (m_connectionMaxLayer < 74)
        {
            out.WriteUInt8(2); // audio codecs count
            out.WriteUInt8(CODEC_OPUS_OLD);
            out.WriteUInt8(0);
            out.WriteUInt8(0);
            out.WriteUInt8(0);
            out.WriteInt32(CODEC_OPUS);
            out.WriteUInt8(0); // video codecs count (decode)
            out.WriteUInt8(0); // video codecs count (encode)
        }
        else
        {
            out.WriteUInt8(std::uint8_t{1});
            out.WriteInt32(CODEC_OPUS);
            std::vector<std::uint32_t> decoders = m_config.enableVideoReceive ? video::VideoRenderer::GetAvailableDecoders() : std::vector<std::uint32_t>();
            std::vector<std::uint32_t> encoders = m_config.enableVideoSend ? video::VideoSource::GetAvailableEncoders() : std::vector<std::uint32_t>();
            out.WriteUInt8(static_cast<std::uint8_t>(decoders.size()));
            for (std::uint32_t id : decoders)
            {
                out.WriteUInt32(id);
            }
            if (m_connectionMaxLayer >= 92)
                out.WriteUInt8(static_cast<std::uint8_t>(video::VideoRenderer::GetMaximumResolution()));
            else
                out.WriteUInt8(std::uint8_t{0});
        }
        std::size_t outLength = out.GetLength();
        SendOrEnqueuePacket(PendingOutgoingPacket {
            /*.seq=*/initSeq,
            /*.type=*/PktType::INIT,
            /*.len=*/outLength,
            /*.data=*/Buffer(std::move(out)),
            /*.endpoint=*/e.id});
    }

    if (m_state == State::WAIT_INIT)
        SetState(State::WAIT_INIT_ACK);
    m_messageThread.Post([this] {
        if (m_state == State::WAIT_INIT_ACK)
        {
            SendInit();
        }
    },
        0.5);
}

void VoIPController::InitUDPProxy()
{
    if (m_realUdpSocket != m_udpSocket)
    {
        m_udpSocket->Close();
        delete m_udpSocket;
        m_udpSocket = m_realUdpSocket;
    }
    char sbuf[128];
    snprintf(sbuf, sizeof(sbuf), "%s:%u", m_proxyAddress.c_str(), m_proxyPort);
    std::string proxyHostPort(sbuf);
    if (proxyHostPort == m_lastTestedProxyServer && !m_proxySupportsUDP)
    {
        LOGI("Proxy does not support UDP - using UDP directly instead");
        m_messageThread.Post(std::bind(&VoIPController::ResetUdpAvailability, this));
        return;
    }

    NetworkSocket* tcp = NetworkSocket::Create(NetworkProtocol::TCP);
    tcp->Connect(m_resolvedProxyAddress, m_proxyPort);

    std::vector<NetworkSocket*> writeSockets;
    std::vector<NetworkSocket*> readSockets;
    std::vector<NetworkSocket*> errorSockets;

    while (!tcp->IsFailed() && !tcp->IsReadyToSend())
    {
        writeSockets.push_back(tcp);
        if (!NetworkSocket::Select(readSockets, writeSockets, errorSockets, m_selectCanceller))
        {
            LOGW("Select canceled while waiting for proxy control socket to connect");
            delete tcp;
            return;
        }
    }
    LOGV("UDP proxy control socket ready to send");
    NetworkSocketSOCKS5Proxy* udpProxy = new NetworkSocketSOCKS5Proxy(tcp, m_realUdpSocket, m_proxyUsername, m_proxyPassword);
    udpProxy->OnReadyToSend();
    writeSockets.clear();
    while (!udpProxy->IsFailed() && !tcp->IsFailed() && !udpProxy->IsReadyToSend())
    {
        readSockets.clear();
        errorSockets.clear();
        readSockets.push_back(tcp);
        errorSockets.push_back(tcp);
        if (!NetworkSocket::Select(readSockets, writeSockets, errorSockets, m_selectCanceller))
        {
            LOGW("Select canceled while waiting for UDP proxy to initialize");
            delete udpProxy;
            return;
        }
        if (!readSockets.empty())
            udpProxy->OnReadyToReceive();
    }
    LOGV("UDP proxy initialized");

    if (udpProxy->IsFailed())
    {
        udpProxy->Close();
        delete udpProxy;
        m_proxySupportsUDP = false;
    }
    else
    {
        m_udpSocket = udpProxy;
    }
    m_messageThread.Post(std::bind(&VoIPController::ResetUdpAvailability, this));
}

void VoIPController::RunRecvThread()
{
    LOGI("Receive thread starting");
    if (m_proxyProtocol == Proxy::SOCKS5)
    {
        m_resolvedProxyAddress = NetworkSocket::ResolveDomainName(m_proxyAddress);
        if (m_resolvedProxyAddress.IsEmpty())
        {
            LOGW("Error resolving proxy address %s", m_proxyAddress.c_str());
            SetState(State::FAILED);
            return;
        }
    }
    else
    {
        m_udpConnectivityState = UdpState::PING_PENDING;
        m_udpPingTimeoutID = m_messageThread.Post(std::bind(&VoIPController::SendUdpPings, this), 0.0, 0.5);
    }
    while (m_runReceiver)
    {

        if (m_proxyProtocol == Proxy::SOCKS5 && m_needReInitUdpProxy)
        {
            InitUDPProxy();
            m_needReInitUdpProxy = false;
        }

        std::vector<NetworkSocket*> readSockets;
        std::vector<NetworkSocket*> errorSockets;
        std::vector<NetworkSocket*> writeSockets;
        readSockets.push_back(m_udpSocket);
        errorSockets.push_back(m_realUdpSocket);
        if (!m_realUdpSocket->IsReadyToSend())
            writeSockets.push_back(m_realUdpSocket);

        {
            MutexGuard m(m_endpointsMutex);
            for (std::pair<const std::int64_t, Endpoint>& _e : m_endpoints)
            {
                const Endpoint& e = _e.second;
                if (e.type == Endpoint::Type::TCP_RELAY)
                {
                    if (e.m_socket)
                    {
                        readSockets.push_back(&*e.m_socket);
                        errorSockets.push_back(&*e.m_socket);
                        if (!e.m_socket->IsReadyToSend())
                        {
                            NetworkSocketSOCKS5Proxy* proxy = dynamic_cast<NetworkSocketSOCKS5Proxy*>(&*e.m_socket);
                            if (!proxy || proxy->NeedSelectForSending())
                                writeSockets.push_back(&*e.m_socket);
                        }
                    }
                }
            }
        }

        {
            bool selRes = NetworkSocket::Select(readSockets, writeSockets, errorSockets, m_selectCanceller);
            if (!selRes)
            {
                LOGV("Select canceled");
                continue;
            }
        }
        if (!m_runReceiver)
            return;

        if (!errorSockets.empty())
        {
            if (find(errorSockets.begin(), errorSockets.end(), m_realUdpSocket) != errorSockets.end())
            {
                LOGW("UDP socket failed");
                SetState(State::FAILED);
                return;
            }
            MutexGuard m(m_endpointsMutex);
            for (NetworkSocket*& socket : errorSockets)
            {
                for (std::pair<const std::int64_t, Endpoint>& _e : m_endpoints)
                {
                    Endpoint& e = _e.second;
                    if (e.m_socket && &*e.m_socket == socket)
                    {
                        e.m_socket->Close();
                        e.m_socket.reset();
                        LOGI("Closing failed TCP socket for %s:%u", e.GetAddress().ToString().c_str(), e.port);
                    }
                }
            }
            continue;
        }

        for (NetworkSocket*& socket : readSockets)
        {
            //while(packet.length){
            NetworkPacket packet = socket->Receive();
            if (packet.address.IsEmpty())
            {
                LOGE("Packet has null address. This shouldn't happen.");
                continue;
            }
            if (packet.data.IsEmpty())
            {
                LOGE("Packet has zero length.");
                continue;
            }
            //LOGV("Received %d bytes from %s:%d at %.5lf", len, packet.address->ToString().c_str(), packet.port, GetCurrentTime());
            m_messageThread.Post(bind(&VoIPController::NetworkPacketReceived, this, std::make_shared<NetworkPacket>(std::move(packet))));
        }

        if (!writeSockets.empty())
        {
            m_messageThread.Post(std::bind(&VoIPController::TrySendQueuedPackets, this));
        }
    }
    LOGI("=== recv thread exiting ===");
}

void VoIPController::TrySendQueuedPackets()
{
    ENFORCE_MSG_THREAD;

    for (std::vector<PendingOutgoingPacket>::iterator opkt = m_sendQueue.begin(); opkt != m_sendQueue.end();)
    {
        Endpoint* endpoint = GetEndpointForPacket(*opkt);
        if (!endpoint)
        {
            opkt = m_sendQueue.erase(opkt);
            LOGE("SendQueue contained packet for nonexistent endpoint");
            continue;
        }
        bool canSend;
        if (endpoint->type != Endpoint::Type::TCP_RELAY)
            canSend = m_realUdpSocket->IsReadyToSend();
        else
            canSend = endpoint->m_socket && endpoint->m_socket->IsReadyToSend();
        if (canSend)
        {
            LOGI("Sending queued packet");
            SendOrEnqueuePacket(std::move(*opkt), false);
            opkt = m_sendQueue.erase(opkt);
        }
        else
        {
            ++opkt;
        }
    }
}

bool VoIPController::WasOutgoingPacketAcknowledged(std::uint32_t seq)
{
    RecentOutgoingPacket* pkt = GetRecentOutgoingPacket(seq);
    if (!pkt)
        return false;
    return pkt->ackTime != 0.0;
}

VoIPController::RecentOutgoingPacket* VoIPController::GetRecentOutgoingPacket(std::uint32_t seq)
{
    for (RecentOutgoingPacket& opkt : m_recentOutgoingPackets)
    {
        if (opkt.seq == seq)
        {
            return &opkt;
        }
    }
    return nullptr;
}

void VoIPController::NetworkPacketReceived(std::shared_ptr<NetworkPacket> _packet)
{
    ENFORCE_MSG_THREAD;

    NetworkPacket& packet = *_packet;

    std::int64_t srcEndpointID = 0;

    if (!packet.address.isIPv6)
    {
        for (std::pair<const std::int64_t, Endpoint>& _e : m_endpoints)
        {
            const Endpoint& e = _e.second;
            if (e.address == packet.address && e.port == packet.port)
            {
                if ((e.type != Endpoint::Type::TCP_RELAY && packet.protocol == NetworkProtocol::UDP) || (e.type == Endpoint::Type::TCP_RELAY && packet.protocol == NetworkProtocol::TCP))
                {
                    srcEndpointID = e.id;
                    break;
                }
            }
        }
        if (!srcEndpointID && packet.protocol == NetworkProtocol::UDP)
        {
            try
            {
                Endpoint& p2p = GetEndpointByType(Endpoint::Type::UDP_P2P_INET);
                if (p2p.m_rtts[0] == 0.0 && p2p.address.PrefixMatches(24, packet.address))
                {
                    LOGD("Packet source matches p2p endpoint partially: %s:%u", packet.address.ToString().c_str(), packet.port);
                    srcEndpointID = p2p.id;
                }
            }
            catch (const std::out_of_range&)
            {
            }
        }
    }
    else
    {
        for (std::pair<const std::int64_t, Endpoint>& _e : m_endpoints)
        {
            const Endpoint& e = _e.second;
            if (e.v6address == packet.address && e.port == packet.port && e.IsIPv6Only())
            {
                if ((e.type != Endpoint::Type::TCP_RELAY && packet.protocol == NetworkProtocol::UDP) || (e.type == Endpoint::Type::TCP_RELAY && packet.protocol == NetworkProtocol::TCP))
                {
                    srcEndpointID = e.id;
                    break;
                }
            }
        }
    }

    if (!srcEndpointID)
    {
        LOGW("Received a packet from unknown source %s:%u", packet.address.ToString().c_str(), packet.port);
        return;
    }
    /*if(len<=0){
		//LOGW("error receiving: %d / %s", errno, strerror(errno));
		continue;
	}*/
    if (IS_MOBILE_NETWORK(m_networkType))
        m_stats.bytesRecvdMobile += static_cast<std::uint64_t>(packet.data.Length());
    else
        m_stats.bytesRecvdWifi += static_cast<std::uint64_t>(packet.data.Length());
    try
    {
        ProcessIncomingPacket(packet, m_endpoints.at(srcEndpointID));
    }
    catch (const std::out_of_range& x)
    {
        LOGW("Error parsing packet: %s", x.what());
    }
}

void VoIPController::ProcessIncomingPacket(NetworkPacket& packet, Endpoint& srcEndpoint)
{
    ENFORCE_MSG_THREAD;

    std::uint8_t* buffer = *packet.data;
    std::size_t len = packet.data.Length();
    BufferInputStream in(packet.data);
    bool hasPeerTag = false;
    if (m_peerVersion < 9 || srcEndpoint.type == Endpoint::Type::UDP_RELAY || srcEndpoint.type == Endpoint::Type::TCP_RELAY)
    {
        if (std::memcmp(buffer,
                        (srcEndpoint.type == Endpoint::Type::UDP_RELAY || srcEndpoint.type == Endpoint::Type::TCP_RELAY)
                        ? reinterpret_cast<void*>(srcEndpoint.peerTag) : reinterpret_cast<void*>(m_callID),
                        16) != 0)
        {
            LOGW("Received packet has wrong peerTag");
            return;
        }
        in.Seek(16);
        hasPeerTag = true;
    }
    if (in.Remaining() >= 16 && (srcEndpoint.type == Endpoint::Type::UDP_RELAY || srcEndpoint.type == Endpoint::Type::TCP_RELAY)
        && *reinterpret_cast<std::uint64_t*>(buffer + 16) == 0xFFFFFFFFFFFFFFFFLL && *reinterpret_cast<std::uint32_t*>(buffer + 24) == 0xFFFFFFFF)
    {
        // relay special request response
        in.Seek(16 + 12);
        std::uint32_t tlid = in.ReadUInt32();

        if (tlid == TLID_UDP_REFLECTOR_SELF_INFO)
        {
            if (srcEndpoint.type == Endpoint::Type::UDP_RELAY /*&& udpConnectivityState==Udp::PING_SENT*/ && in.Remaining() >= 32)
            {
                std::int32_t date = in.ReadInt32();
                std::int64_t queryID = in.ReadInt64();
                std::uint8_t myIP[16];
                in.ReadBytes(myIP, 16);
                std::int16_t myPort = in.ReadInt16();
                //udpConnectivityState=Udp::AVAILABLE;
                double selfRTT = 0.0;
                srcEndpoint.m_udpPongCount++;
                srcEndpoint.m_totalUdpPingReplies++;
                if (srcEndpoint.m_udpPingTimes.find(queryID) != srcEndpoint.m_udpPingTimes.end())
                {
                    double sendTime = srcEndpoint.m_udpPingTimes[queryID];
                    srcEndpoint.m_udpPingTimes.erase(queryID);
                    srcEndpoint.m_selfRtts.Add(selfRTT = GetCurrentTime() - sendTime);
                }
                LOGV("Received UDP ping reply from %s:%d: date=%d, queryID=%ld, my IP=%s, my port=%d, selfRTT=%f", srcEndpoint.address.ToString().c_str(), srcEndpoint.port, date, (long int)queryID, NetworkAddress::IPv4(*reinterpret_cast<std::uint32_t*>(myIP + 12)).ToString().c_str(), myPort, selfRTT);
                if (srcEndpoint.IsIPv6Only() && !m_didSendIPv6Endpoint)
                {
                    NetworkAddress realAddr = NetworkAddress::IPv6(myIP);
                    if (realAddr == m_myIPv6)
                    {
                        LOGI("Public IPv6 matches local address");
                        m_useIPv6 = true;
                        if (m_allowP2p)
                        {
                            m_didSendIPv6Endpoint = true;
                            BufferOutputStream o(18);
                            o.WriteBytes(myIP, 16);
                            o.WriteUInt16(m_udpSocket->GetLocalPort());
                            Buffer b(std::move(o));
                            SendExtra(b, EXTRA_TYPE_IPV6_ENDPOINT);
                        }
                    }
                }
            }
        }
        else if (tlid == TLID_UDP_REFLECTOR_PEER_INFO)
        {
            if (in.Remaining() >= 16)
            {
                std::uint32_t myAddr   = in.ReadUInt32();
                std::uint16_t myPort   = in.ReadUInt16();
                std::uint32_t peerAddr = in.ReadUInt32();
                std::uint16_t peerPort = in.ReadUInt16();

                constexpr std::int64_t p2pID = static_cast<std::int64_t>(FOURCC('P', '2', 'P', '4')) << 32;
                constexpr std::int64_t lanID = static_cast<std::int64_t>(FOURCC('L', 'A', 'N', '4')) << 32;

                if (m_currentEndpoint == p2pID || m_currentEndpoint == lanID)
                    m_currentEndpoint = m_preferredRelay;

                if (m_endpoints.find(lanID) != m_endpoints.end())
                {
                    MutexGuard m(m_endpointsMutex);
                    m_endpoints.erase(lanID);
                }

                std::uint8_t peerTag[16];
                LOGW("Received reflector peer info, my=%s:%u, peer=%s:%u", NetworkAddress::IPv4(myAddr).ToString().c_str(), myPort, NetworkAddress::IPv4(peerAddr).ToString().c_str(), peerPort);
                if (m_waitingForRelayPeerInfo)
                {
                    Endpoint p2p(p2pID, peerPort, NetworkAddress::IPv4(peerAddr), NetworkAddress::Empty(), Endpoint::Type::UDP_P2P_INET, peerTag);
                    {
                        MutexGuard m(m_endpointsMutex);
                        m_endpoints[p2pID] = p2p;
                    }
                    if (myAddr == peerAddr)
                    {
                        LOGW("Detected LAN");
                        NetworkAddress lanAddr = NetworkAddress::IPv4(0);
                        m_udpSocket->GetLocalInterfaceInfo(&lanAddr, nullptr);

                        BufferOutputStream pkt(8);
                        pkt.WriteUInt32(lanAddr.addr.ipv4);
                        pkt.WriteUInt16(m_udpSocket->GetLocalPort());
                        if (m_peerVersion < 6)
                        {
                            SendPacketReliably(PktType::LAN_ENDPOINT, pkt.GetBuffer(), pkt.GetLength(), 0.5, 10);
                        }
                        else
                        {
                            Buffer buf(std::move(pkt));
                            SendExtra(buf, EXTRA_TYPE_LAN_ENDPOINT);
                        }
                    }
                    m_waitingForRelayPeerInfo = false;
                }
            }
        }
        else
        {
            LOGV("Received relay response with unknown tl id: 0x%08X", tlid);
        }
        return;
    }
    if (in.Remaining() < 40)
    {
        LOGV("Received packet is too small");
        return;
    }

    bool retryWith2 = false;
    std::size_t innerLen = 0;
    bool shortFormat = m_peerVersion >= 8 || (!m_peerVersion && m_connectionMaxLayer >= 92);

    if (!m_useMTProto2)
    {
        std::uint8_t fingerprint[8], msgHash[16];
        in.ReadBytes(fingerprint, 8);
        in.ReadBytes(msgHash, 16);
        std::uint8_t key[32], iv[32];
        KDF(msgHash, m_isOutgoing ? 8 : 0, key, iv);
        std::vector<std::uint8_t> aesOut(MSC_STACK_FALLBACK(in.Remaining(), 1500));
        if (in.Remaining() > aesOut.size())
            return;
        crypto.aes_ige_decrypt(buffer + in.GetOffset(), aesOut.data(), in.Remaining(), key, iv);
        BufferInputStream _in(aesOut.data(), in.Remaining());
        std::uint8_t sha[SHA1_LENGTH];
        std::uint32_t _len = _in.ReadUInt32();
        if (_len > _in.Remaining())
            _len = static_cast<std::uint32_t>(_in.Remaining());
        crypto.sha1(aesOut.data(), static_cast<std::size_t>(_len) + 4, sha);
        if (memcmp(msgHash, sha + (SHA1_LENGTH - 16), 16) != 0)
        {
            LOGW("Received packet has wrong hash after decryption");
            if (m_state == State::WAIT_INIT || m_state == State::WAIT_INIT_ACK)
                retryWith2 = true;
            else
                return;
        }
        else
        {
            std::memcpy(buffer + in.GetOffset(), aesOut.data(), in.Remaining());
            in.ReadInt32();
        }
    }

    if (m_useMTProto2 || retryWith2)
    {
        if (hasPeerTag)
            in.Seek(16); // peer tag

        std::uint8_t fingerprint[8], msgKey[16];
        if (!shortFormat)
        {
            in.ReadBytes(fingerprint, 8);
            if (memcmp(fingerprint, m_keyFingerprint, 8) != 0)
            {
                LOGW("Received packet has wrong key fingerprint");
                return;
            }
        }
        in.ReadBytes(msgKey, 16);

        std::uint8_t decrypted[1500];
        std::uint8_t aesKey[32], aesIv[32];
        KDF2(msgKey, m_isOutgoing ? 8 : 0, aesKey, aesIv);
        std::size_t decryptedLen = in.Remaining();
        if (decryptedLen > sizeof(decrypted))
            return;
        if (decryptedLen % 16 != 0)
        {
            LOGW("wrong decrypted length");
            return;
        }

        crypto.aes_ige_decrypt(*packet.data + in.GetOffset(), decrypted, decryptedLen, aesKey, aesIv);

        in = BufferInputStream(decrypted, decryptedLen);
        //LOGD("received packet length: %d", in.ReadInt32());
        std::size_t sizeSize = shortFormat ? 0 : 4;

        BufferOutputStream buf(decryptedLen + 32);
        std::size_t x = m_isOutgoing ? 8 : 0;
        buf.WriteBytes(m_encryptionKey + 88 + x, 32);
        buf.WriteBytes(decrypted + sizeSize, decryptedLen - sizeSize);
        std::uint8_t msgKeyLarge[32];
        crypto.sha256(buf.GetBuffer(), buf.GetLength(), msgKeyLarge);

        if (std::memcmp(msgKey, msgKeyLarge + 8, 16) != 0)
        {
            LOGW("Received packet has wrong hash");
            return;
        }

        innerLen = (shortFormat ? in.ReadUInt16() : in.ReadUInt32());
        if (innerLen > decryptedLen - sizeSize)
        {
            LOGW("Received packet has wrong inner length (%d with total of %u)", static_cast<int>(innerLen), static_cast<unsigned int>(decryptedLen));
            return;
        }
        if (decryptedLen - innerLen < (shortFormat ? 16 : 12))
        {
            LOGW("Received packet has too little padding (%u)", static_cast<unsigned int>(decryptedLen - innerLen));
            return;
        }
        std::memcpy(buffer, decrypted + (shortFormat ? 2 : 4), innerLen);
        in = BufferInputStream(buffer, innerLen);
        if (retryWith2)
        {
            LOGD("Successfully decrypted packet in MTProto2.0 fallback, upgrading");
            m_useMTProto2 = true;
        }
    }

    m_lastRecvPacketTime = GetCurrentTime();

    if (m_state == State::RECONNECTING)
    {
        LOGI("Received a valid packet while reconnecting - setting state to established");
        SetState(State::ESTABLISHED);
    }

    if (srcEndpoint.type == Endpoint::Type::UDP_P2P_INET && !srcEndpoint.IsIPv6Only())
    {
        if (srcEndpoint.port != packet.port || srcEndpoint.address != packet.address)
        {
            if (!packet.address.isIPv6)
            {
                LOGI("Incoming packet was decrypted successfully, changing P2P endpoint to %s:%u", packet.address.ToString().c_str(), packet.port);
                srcEndpoint.address = packet.address;
                srcEndpoint.port = packet.port;
            }
        }
    }

    /*decryptedAudioBlock random_id:long random_bytes:string flags:# voice_call_id:flags.2?int128 in_seq_no:flags.4?int out_seq_no:flags.4?int
 * recent_received_mask:flags.5?int proto:flags.3?int extra:flags.1?string raw_data:flags.0?string = DecryptedAudioBlock
simpleAudioBlock random_id:long random_bytes:string raw_data:string = DecryptedAudioBlock;
*/
    std::uint32_t ackId, pseq, acks;
    PktType type;
    std::uint8_t pflags;
    std::size_t packetInnerLen = 0;
    if (shortFormat)
    {
        type = static_cast<PktType>(in.ReadUInt8());
        ackId = in.ReadUInt32();
        pseq = in.ReadUInt32();
        acks = in.ReadUInt32();
        pflags = in.ReadUInt8();
        packetInnerLen = innerLen - 14;
    }
    else
    {
        std::uint32_t tlid = in.ReadUInt32();
        if (tlid == TLID_DECRYPTED_AUDIO_BLOCK)
        {
            in.ReadInt64(); // random id
            std::int32_t randLen = in.ReadTlLength();
            in.Seek(in.GetOffset() + static_cast<std::size_t>(randLen + pad4(randLen)));
            std::uint32_t flags = in.ReadUInt32();
            type = static_cast<PktType>((flags >> 24) & 0xFF);
            if (!(flags & PFLAG_HAS_SEQ && flags & PFLAG_HAS_RECENT_RECV))
            {
                LOGW("Received packet doesn't have PFLAG_HAS_SEQ, PFLAG_HAS_RECENT_RECV, or both");

                return;
            }
            if (flags & PFLAG_HAS_CALL_ID)
            {
                std::uint8_t pktCallID[16];
                in.ReadBytes(pktCallID, 16);
                if (memcmp(pktCallID, m_callID, 16) != 0)
                {
                    LOGW("Received packet has wrong call id");

                    m_lastError = Error::UNKNOWN;
                    SetState(State::FAILED);
                    return;
                }
            }
            ackId = in.ReadUInt32();
            pseq = in.ReadUInt32();
            acks = in.ReadUInt32();
            if (flags & PFLAG_HAS_PROTO)
            {
                std::uint32_t proto = in.ReadUInt32();
                if (proto != PROTOCOL_NAME)
                {
                    LOGW("Received packet uses wrong protocol");

                    m_lastError = Error::INCOMPATIBLE;
                    SetState(State::FAILED);
                    return;
                }
            }
            if (flags & PFLAG_HAS_EXTRA)
            {
                int extraLen = in.ReadTlLength();
                in.Seek(in.GetOffset() + static_cast<std::size_t>(extraLen + pad4(extraLen)));
            }
            if (flags & PFLAG_HAS_DATA)
            {
                packetInnerLen = static_cast<std::size_t>(in.ReadTlLength());
            }
            pflags = 0;
        }
        else if (tlid == TLID_SIMPLE_AUDIO_BLOCK)
        {
            in.ReadInt64(); // random id
            int randLen = in.ReadTlLength();
            in.Seek(in.GetOffset() + static_cast<std::size_t>(randLen + pad4(randLen)));
            packetInnerLen = static_cast<std::size_t>(in.ReadTlLength());
            type = static_cast<PktType>(in.ReadUInt8());
            ackId = in.ReadUInt32();
            pseq = in.ReadUInt32();
            acks = in.ReadUInt32();
            if (m_peerVersion >= 6)
                pflags = in.ReadUInt8();
            else
                pflags = 0;
        }
        else
        {
            LOGW("Received a packet of unknown type %08X", tlid);

            return;
        }
    }
    m_packetsReceived++;

    if (seqgt(pseq, m_lastRemoteSeq - MAX_RECENT_PACKETS))
    {
        if (find(m_recentIncomingPackets.begin(), m_recentIncomingPackets.end(), pseq) != m_recentIncomingPackets.end())
        {
            LOGW("Received duplicated packet for seq %u", pseq);
            return;
        }
        m_recentIncomingPackets.push_back(pseq);
        while (m_recentIncomingPackets.size() > MAX_RECENT_PACKETS)
            m_recentIncomingPackets.erase(m_recentIncomingPackets.begin());
        if (seqgt(pseq, m_lastRemoteSeq))
            m_lastRemoteSeq = pseq;
    }
    else
    {
        LOGW("Packet %u is out of order and too late", pseq);
        return;
    }

    if (pflags & XPFLAG_HAS_EXTRA)
    {
        std::uint8_t extraCount = in.ReadUInt8();
        for (int i = 0; i < extraCount; i++)
        {
            std::size_t extraLen = in.ReadUInt8();
            Buffer xbuffer(extraLen);
            in.ReadBytes(*xbuffer, extraLen);
            ProcessExtraData(xbuffer);
        }
    }

    std::uint32_t recvTS = 0;
    if (pflags & XPFLAG_HAS_RECV_TS)
    {
        recvTS = in.ReadUInt32();
    }
    if (seqgt(ackId, m_lastRemoteAckSeq))
    {

        if (m_waitingForAcks && m_lastRemoteAckSeq >= m_firstSentPing)
        {
            m_rttHistory.Reset();
            m_waitingForAcks = false;
            m_dontSendPackets = 10;
            m_messageThread.Post([this] {
                m_dontSendPackets = 0;
            },
                1.0);
            LOGI("resuming sending");
        }
        std::vector<std::uint32_t> peerAcks;
        m_lastRemoteAckSeq = ackId;
        m_conctl->PacketAcknowledged(ackId);
        peerAcks.push_back(ackId);
        for (unsigned int i = 0; i < 32; i++)
        {
            if ((acks >> (31 - i)) & 1)
            {
                peerAcks.push_back(ackId - (i + 1));
            }
        }

        for (RecentOutgoingPacket& opkt : m_recentOutgoingPackets)
        {
            if (opkt.ackTime != 0.0)
                continue;
            if (find(peerAcks.begin(), peerAcks.end(), opkt.seq) != peerAcks.end())
            {
                opkt.ackTime = GetCurrentTime();
                if (opkt.lost)
                {
                    LOGW("acknowledged lost packet %u", opkt.seq);
                    m_sendLosses--;
                }
                if (opkt.sender && !opkt.lost)
                { // don't report lost packets as acknowledged to PacketSenders
                    opkt.sender->PacketAcknowledged(opkt.seq, opkt.sendTime, recvTS / 1000.0, opkt.type, opkt.size);
                }

                // TODO move this to a PacketSender
                m_conctl->PacketAcknowledged(opkt.seq);
            }
        }

        if (m_peerVersion < 6)
        {
            for (unsigned int i = 0; i < m_queuedPackets.size(); i++)
            {
                QueuedPacket& qp = m_queuedPackets[i];
                bool didAck = false;
                for (std::size_t j = 0; j < 16; ++j)
                {
                    LOGD("queued packet %u, seq %u=%u", i, static_cast<unsigned int>(j), qp.seqs[j]);
                    if (qp.seqs[j] == 0)
                        break;
                    int remoteAcksIndex = static_cast<int>(m_lastRemoteAckSeq - qp.seqs[j]);
                    //LOGV("remote acks index %u, value %f", remoteAcksIndex, remoteAcksIndex>=0 && remoteAcksIndex<32 ? remoteAcks[remoteAcksIndex] : -1);
                    if (seqgt(m_lastRemoteAckSeq, qp.seqs[j]) && remoteAcksIndex >= 0 && remoteAcksIndex < 32)
                    {
                        for (RecentOutgoingPacket& opkt : m_recentOutgoingPackets)
                        {
                            if (opkt.seq == qp.seqs[j] && opkt.ackTime > 0)
                            {
                                LOGD("did ack seq %u, removing", qp.seqs[j]);
                                didAck = true;
                                break;
                            }
                        }
                        if (didAck)
                            break;
                    }
                }
                if (didAck)
                {
                    m_queuedPackets.erase(m_queuedPackets.begin() + i);
                    i--;
                    continue;
                }
            }
        }
        else
        {
            for (std::vector<UnacknowledgedExtraData>::iterator x = m_currentExtras.begin(); x != m_currentExtras.end();)
            {
                if (x->firstContainingSeq != 0 && (m_lastRemoteAckSeq == x->firstContainingSeq || seqgt(m_lastRemoteAckSeq, x->firstContainingSeq)))
                {
                    LOGV("Peer acknowledged extra type %u length %u", x->type, static_cast<unsigned int>(x->data.Length()));
                    ProcessAcknowledgedOutgoingExtra(*x);
                    x = m_currentExtras.erase(x);
                    continue;
                }
                ++x;
            }
        }
    }

    Endpoint* _currentEndpoint = &m_endpoints.at(m_currentEndpoint);
    if (   srcEndpoint.id != m_currentEndpoint
        && (srcEndpoint.type == Endpoint::Type::UDP_RELAY || srcEndpoint.type == Endpoint::Type::TCP_RELAY)
        && ((_currentEndpoint->type != Endpoint::Type::UDP_RELAY && _currentEndpoint->type != Endpoint::Type::TCP_RELAY) || _currentEndpoint->m_averageRTT == 0))
    {
        if (seqgt(m_lastSentSeq - 32, m_lastRemoteAckSeq))
        {
            m_currentEndpoint = srcEndpoint.id;
            _currentEndpoint = &srcEndpoint;
            LOGI("Peer network address probably changed, switching to relay");
            if (m_allowP2p)
                SendPublicEndpointsRequest();
        }
    }

    if (m_config.logPacketStats)
    {
        DebugLoggedPacket dpkt = {
            static_cast<std::int32_t>(pseq),
            GetCurrentTime() - m_connectionInitTime,
            static_cast<std::int32_t>(packet.data.Length())};
        m_debugLoggedPackets.push_back(dpkt);
        if (m_debugLoggedPackets.size() >= 2500)
        {
            m_debugLoggedPackets.erase(m_debugLoggedPackets.begin(), m_debugLoggedPackets.begin() + 500);
        }
    }

    m_unacknowledgedIncomingPacketCount++;
    if (m_unacknowledgedIncomingPacketCount > m_unackNopThreshold)
    {
        //LOGV("Sending nop packet as ack");
        SendNopPacket();
    }

#ifdef LOG_PACKETS
    LOGV("Received: from=%s:%u, seq=%u, length=%u, type=%s", srcEndpoint.GetAddress().ToString().c_str(), srcEndpoint.port, pseq, (unsigned int)packet.data.Length(), GetPacketTypeString(type).c_str());
#endif

    //LOGV("acks: %u -> %.2lf, %.2lf, %.2lf, %.2lf, %.2lf, %.2lf, %.2lf, %.2lf", lastRemoteAckSeq, remoteAcks[0], remoteAcks[1], remoteAcks[2], remoteAcks[3], remoteAcks[4], remoteAcks[5], remoteAcks[6], remoteAcks[7]);
    //LOGD("recv: %u -> %.2lf, %.2lf, %.2lf, %.2lf, %.2lf, %.2lf, %.2lf, %.2lf", lastRemoteSeq, recvPacketTimes[0], recvPacketTimes[1], recvPacketTimes[2], recvPacketTimes[3], recvPacketTimes[4], recvPacketTimes[5], recvPacketTimes[6], recvPacketTimes[7]);
    //LOGI("RTT = %.3lf", GetAverageRTT());
    //LOGV("Packet %u type is %d", pseq, type);
    if (static_cast<PktType>(type) == PktType::INIT)
    {
        LOGD("Received init");
        std::int32_t ver = in.ReadInt32();
        if (!m_receivedInit)
            m_peerVersion = ver;
        LOGI("Peer version is %d", m_peerVersion);
        std::uint32_t minVer = in.ReadUInt32();
        if (minVer > PROTOCOL_VERSION || m_peerVersion < MIN_PROTOCOL_VERSION)
        {
            m_lastError = Error::INCOMPATIBLE;

            SetState(State::FAILED);
            return;
        }
        std::uint32_t flags = in.ReadUInt32();
        if (!m_receivedInit)
        {
            if (flags & INIT_FLAG_DATA_SAVING_ENABLED)
            {
                m_dataSavingRequestedByPeer = true;
                UpdateDataSavingState();
                UpdateAudioBitrateLimit();
            }
            if (flags & INIT_FLAG_GROUP_CALLS_SUPPORTED)
            {
                m_peerCapabilities |= TGVOIP_PEER_CAP_GROUP_CALLS;
            }
            if (flags & INIT_FLAG_VIDEO_RECV_SUPPORTED)
            {
                m_peerCapabilities |= TGVOIP_PEER_CAP_VIDEO_DISPLAY;
            }
            if (flags & INIT_FLAG_VIDEO_SEND_SUPPORTED)
            {
                m_peerCapabilities |= TGVOIP_PEER_CAP_VIDEO_CAPTURE;
            }
        }

        std::uint8_t numSupportedAudioCodecs = in.ReadUInt8();
        for (int i = 0; i < numSupportedAudioCodecs; ++i)
        {
            if (m_peerVersion < 5)
                in.ReadUInt8(); // ignore for now
            else
                in.ReadInt32();
        }
        if (!m_receivedInit && ((flags & INIT_FLAG_VIDEO_SEND_SUPPORTED && m_config.enableVideoReceive) || (flags & INIT_FLAG_VIDEO_RECV_SUPPORTED && m_config.enableVideoSend)))
        {
            LOGD("Peer video decoders:");
            std::uint8_t numSupportedVideoDecoders = in.ReadUInt8();
            for (int i = 0; i < numSupportedVideoDecoders; ++i)
            {
                std::uint32_t id = in.ReadUInt32();
                m_peerVideoDecoders.push_back(id);
                char* _id = reinterpret_cast<char*>(&id);
                LOGD("%c%c%c%c", _id[3], _id[2], _id[1], _id[0]);
            }
            m_protocolInfo.maxVideoResolution = in.ReadUInt8();

            SetupOutgoingVideoStream();
        }

        BufferOutputStream out(1024);

        out.WriteInt32(PROTOCOL_VERSION);
        out.WriteInt32(MIN_PROTOCOL_VERSION);

        out.WriteUInt8(static_cast<std::uint8_t>(m_outgoingStreams.size()));
        for (std::vector<std::shared_ptr<Stream>>::iterator s = m_outgoingStreams.begin(); s != m_outgoingStreams.end(); ++s)
        {
            out.WriteUInt8((*s)->id);
            out.WriteUInt8((*s)->type);
            if (m_peerVersion < 5)
                out.WriteUInt8(static_cast<std::uint8_t>((*s)->codec == CODEC_OPUS ? CODEC_OPUS_OLD : 0));
            else
                out.WriteUInt32((*s)->codec);
            out.WriteUInt16((*s)->frameDuration);
            out.WriteUInt8((*s)->enabled ? 1 : 0);
        }
        LOGI("Sending init ack");
        std::size_t outLength = out.GetLength();
        SendOrEnqueuePacket(PendingOutgoingPacket {
            /*.seq=*/GenerateOutSeq(),
            /*.type=*/PktType::INIT_ACK,
            /*.len=*/outLength,
            /*.data=*/Buffer(std::move(out)),
            /*.endpoint=*/0});
        if (!m_receivedInit)
        {
            m_receivedInit = true;
            if ((srcEndpoint.type == Endpoint::Type::UDP_RELAY && m_udpConnectivityState != UdpState::BAD && m_udpConnectivityState != UdpState::NOT_AVAILABLE) || srcEndpoint.type == Endpoint::Type::TCP_RELAY)
            {
                m_currentEndpoint = srcEndpoint.id;
                if (srcEndpoint.type == Endpoint::Type::UDP_RELAY || (m_useTCP && srcEndpoint.type == Endpoint::Type::TCP_RELAY))
                    m_preferredRelay = srcEndpoint.id;
            }
        }
        if (!m_audioStarted && m_receivedInitAck)
        {
            StartAudio();
            m_audioStarted = true;
        }
    }
    if (type == PktType::INIT_ACK)
    {
        LOGD("Received init ack");

        if (!m_receivedInitAck)
        {
            m_receivedInitAck = true;

            m_messageThread.Cancel(m_initTimeoutID);
            m_initTimeoutID = MessageThread::INVALID_ID;

            if (packetInnerLen > 10)
            {
                m_peerVersion = in.ReadInt32();
                std::uint32_t minVer = in.ReadUInt32();
                if (minVer > PROTOCOL_VERSION || m_peerVersion < MIN_PROTOCOL_VERSION)
                {
                    m_lastError = Error::INCOMPATIBLE;

                    SetState(State::FAILED);
                    return;
                }
            }
            else
            {
                m_peerVersion = 1;
            }

            LOGI("peer version from init ack %d", m_peerVersion);

            std::uint8_t streamCount = in.ReadUInt8();
            if (streamCount == 0)
                return;

            std::shared_ptr<Stream> incomingAudioStream = nullptr;
            for (int i = 0; i < streamCount; ++i)
            {
                std::shared_ptr<Stream> stm = std::make_shared<Stream>();
                stm->id = in.ReadUInt8();
                stm->type = in.ReadUInt8();
                if (m_peerVersion < 5)
                {
                    std::uint8_t codec = in.ReadUInt8();
                    if (codec == CODEC_OPUS_OLD)
                        stm->codec = CODEC_OPUS;
                }
                else
                {
                    stm->codec = in.ReadUInt32();
                }
                in.ReadInt16();
                stm->frameDuration = 60;
                stm->enabled = in.ReadUInt8() == 1;
                if (stm->type == STREAM_TYPE_VIDEO && m_peerVersion < 9)
                {
                    LOGV("Skipping video stream for old protocol version");
                    continue;
                }
                if (stm->type == STREAM_TYPE_AUDIO)
                {
                    stm->jitterBuffer = std::make_shared<JitterBuffer>(nullptr, stm->frameDuration);
                    if (stm->frameDuration > 50)
                        stm->jitterBuffer->SetMinPacketCount((std::uint32_t)ServerConfig::GetSharedInstance()->GetInt("jitter_initial_delay_60", 2));
                    else if (stm->frameDuration > 30)
                        stm->jitterBuffer->SetMinPacketCount((std::uint32_t)ServerConfig::GetSharedInstance()->GetInt("jitter_initial_delay_40", 4));
                    else
                        stm->jitterBuffer->SetMinPacketCount((std::uint32_t)ServerConfig::GetSharedInstance()->GetInt("jitter_initial_delay_20", 6));
                    stm->decoder = nullptr;
                }
                else if (stm->type == STREAM_TYPE_VIDEO)
                {
                    if (!stm->packetReassembler)
                    {
                        stm->packetReassembler = std::make_shared<PacketReassembler>();
                        stm->packetReassembler->SetCallback(bind(&VoIPController::ProcessIncomingVideoFrame, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
                    }
                }
                else
                {
                    LOGW("Unknown incoming stream type: %d", stm->type);
                    continue;
                }
                m_incomingStreams.push_back(stm);
                if (stm->type == STREAM_TYPE_AUDIO && !incomingAudioStream)
                    incomingAudioStream = stm;
            }
            if (!incomingAudioStream)
                return;

            if (m_peerVersion >= 5 && !m_useMTProto2)
            {
                m_useMTProto2 = true;
                LOGD("MTProto2 wasn't initially enabled for whatever reason but peer supports it; upgrading");
            }

            if (!m_audioStarted && m_receivedInit)
            {
                StartAudio();
                m_audioStarted = true;
            }
            m_messageThread.Post([this] {
                if (m_state == State::WAIT_INIT_ACK)
                {
                    SetState(State::ESTABLISHED);
                }
            },
                ServerConfig::GetSharedInstance()->GetDouble("established_delay_if_no_stream_data", 1.5));
            if (m_allowP2p)
                SendPublicEndpointsRequest();
        }
    }
    if (type == PktType::STREAM_DATA || type == PktType::STREAM_DATA_X2 || type == PktType::STREAM_DATA_X3)
    {
        if (!m_receivedFirstStreamPacket)
        {
            m_receivedFirstStreamPacket = true;
            if (m_state != State::ESTABLISHED && m_receivedInitAck)
            {
                m_messageThread.Post([this]() {
                    SetState(State::ESTABLISHED);
                },
                    .5);
                LOGW("First audio packet - setting state to ESTABLISHED");
            }
        }
        int count;
        switch (type)
        {
        case PktType::STREAM_DATA_X2:
            count = 2;
            break;
        case PktType::STREAM_DATA_X3:
            count = 3;
            break;
        case PktType::STREAM_DATA:
        default:
            count = 1;
            break;
        }
        int i;
        if (srcEndpoint.type == Endpoint::Type::UDP_RELAY && srcEndpoint.id != m_peerPreferredRelay)
        {
            m_peerPreferredRelay = srcEndpoint.id;
        }
        for (i = 0; i < count; i++)
        {
            std::uint8_t streamID = in.ReadUInt8();
            std::uint8_t flags = streamID & std::uint8_t{0xC0};
            streamID &= 0x3F;
            std::uint16_t sdlen = (flags & STREAM_DATA_FLAG_LEN16 ? in.ReadUInt16() : in.ReadUInt8());
            std::uint32_t pts = in.ReadUInt32();
            std::uint8_t fragmentCount = 1;
            std::uint8_t fragmentIndex = 0;
            //LOGD("stream data, pts=%d, len=%d, rem=%d", pts, sdlen, in.Remaining());
            m_audioTimestampIn = pts;
            if (!m_audioOutStarted && m_audioOutput != nullptr)
            {
                MutexGuard m(m_audioIOMutex);
                m_audioOutput->Start();
                m_audioOutStarted = true;
            }
            bool fragmented = static_cast<bool>(sdlen & STREAM_DATA_XFLAG_FRAGMENTED);
            bool extraFEC = static_cast<bool>(sdlen & STREAM_DATA_XFLAG_EXTRA_FEC);
            bool keyframe = static_cast<bool>(sdlen & STREAM_DATA_XFLAG_KEYFRAME);
            if (fragmented)
            {
                fragmentIndex = in.ReadUInt8();
                fragmentCount = in.ReadUInt8();
            }
            sdlen &= 0x7FF;
            if (in.GetOffset() + sdlen > len)
            {
                return;
            }
            std::shared_ptr<Stream> stm;
            for (std::shared_ptr<Stream>& ss : m_incomingStreams)
            {
                if (ss->id == streamID)
                {
                    stm = ss;
                    break;
                }
            }
            if (stm && stm->type == STREAM_TYPE_AUDIO)
            {
                if (stm->jitterBuffer)
                {
                    stm->jitterBuffer->HandleInput(reinterpret_cast<std::uint8_t*>(buffer + in.GetOffset()), sdlen, pts, false);
                    if (extraFEC)
                    {
                        in.Seek(in.GetOffset() + sdlen);
                        std::uint8_t fecCount = in.ReadUInt8();
                        for (unsigned int j = 0; j < fecCount; ++j)
                        {
                            std::uint8_t dlen = in.ReadUInt8();
                            std::uint8_t data[256];
                            in.ReadBytes(data, dlen);
                            stm->jitterBuffer->HandleInput(data, dlen, pts - (fecCount - j) * stm->frameDuration, true);
                        }
                    }
                }
            }
            else if (stm && stm->type == STREAM_TYPE_VIDEO)
            {
                if (stm->packetReassembler)
                {
                    std::uint8_t frameSeq = in.ReadUInt8();
                    Buffer pdata(sdlen);
                    std::uint16_t rotation = 0;
                    if (fragmentIndex == 0)
                    {
                        std::uint8_t _rotation = in.ReadUInt8() & std::uint8_t{VIDEO_ROTATION_MASK};
                        switch (_rotation)
                        {
                        case VIDEO_ROTATION_0:
                            rotation = 0;
                            break;
                        case VIDEO_ROTATION_90:
                            rotation = 90;
                            break;
                        case VIDEO_ROTATION_180:
                            rotation = 180;
                            break;
                        case VIDEO_ROTATION_270:
                            rotation = 270;
                            break;
                        default: // unreachable on sane CPUs
                            abort();
                        }
                        //if(rotation!=stm->rotation){
                        //	stm->rotation=rotation;
                        //	LOGI("Video rotation: %u", rotation);
                        //}
                    }
                    pdata.CopyFrom(buffer + in.GetOffset(), 0, sdlen);
                    stm->packetReassembler->AddFragment(std::move(pdata), fragmentIndex, fragmentCount, pts, frameSeq, keyframe, rotation);
                }
                //LOGV("Received video fragment %u of %u", fragmentIndex, fragmentCount);
            }
            else
            {
                LOGW("received packet for unknown stream %u", static_cast<unsigned int>(streamID));
            }
            if (i < count - 1)
                in.Seek(in.GetOffset() + sdlen);
        }
    }
    if (type == PktType::PING)
    {
        //LOGD("Received ping from %s:%d", srcEndpoint.address.ToString().c_str(), srcEndpoint.port);
        if (srcEndpoint.type != Endpoint::Type::UDP_RELAY && srcEndpoint.type != Endpoint::Type::TCP_RELAY && !m_allowP2p)
        {
            LOGW("Received p2p ping but p2p is disabled by manual override");
            return;
        }
        BufferOutputStream pkt(128);
        pkt.WriteUInt32(pseq);
        std::size_t pktLength = pkt.GetLength();
        SendOrEnqueuePacket(PendingOutgoingPacket {
            /*.seq=*/GenerateOutSeq(),
            /*.type=*/PktType::PONG,
            /*.len=*/pktLength,
            /*.data=*/Buffer(std::move(pkt)),
            /*.endpoint=*/srcEndpoint.id,
        });
    }
    if (type == PktType::PONG)
    {
        if (packetInnerLen >= 4)
        {
            std::uint32_t pingSeq = in.ReadUInt32();
#ifdef LOG_PACKETS
            LOGD("Received pong for ping in seq %u", pingSeq);
#endif
            if (pingSeq == srcEndpoint.m_lastPingSeq)
            {
                srcEndpoint.m_rtts.Add(GetCurrentTime() - srcEndpoint.m_lastPingTime);
                srcEndpoint.m_averageRTT = srcEndpoint.m_rtts.NonZeroAverage();
                LOGD("Current RTT via %s: %.3f, average: %.3f", packet.address.ToString().c_str(), srcEndpoint.m_rtts[0], srcEndpoint.m_averageRTT);
                if (srcEndpoint.m_averageRTT > m_rateMaxAcceptableRTT)
                    m_needRate = true;
            }
        }
    }
    if (type == PktType::STREAM_STATE)
    {
        std::uint8_t id = in.ReadUInt8();
        std::uint8_t enabled = in.ReadUInt8();
        LOGV("Peer stream state: id %u flags %u", id, enabled);
        for (std::vector<std::shared_ptr<Stream>>::iterator s = m_incomingStreams.begin(); s != m_incomingStreams.end(); ++s)
        {
            if ((*s)->id == id)
            {
                (*s)->enabled = enabled == 1;
                UpdateAudioOutputState();
                break;
            }
        }
    }
    if (type == PktType::LAN_ENDPOINT)
    {
        LOGV("received lan endpoint");
        std::uint32_t peerAddr = in.ReadUInt32();
        std::uint16_t peerPort = in.ReadUInt16();
        constexpr std::int64_t lanID = static_cast<std::int64_t>(FOURCC('L', 'A', 'N', '4')) << 32;
        std::uint8_t peerTag[16];
        Endpoint lan(lanID, peerPort, NetworkAddress::IPv4(peerAddr), NetworkAddress::Empty(), Endpoint::Type::UDP_P2P_LAN, peerTag);

        if (m_currentEndpoint == lanID)
            m_currentEndpoint = m_preferredRelay;

        MutexGuard m(m_endpointsMutex);
        m_endpoints[lanID] = lan;
    }
    if (type == PktType::NETWORK_CHANGED && _currentEndpoint->type != Endpoint::Type::UDP_RELAY && _currentEndpoint->type != Endpoint::Type::TCP_RELAY)
    {
        m_currentEndpoint = m_preferredRelay;
        if (m_allowP2p)
            SendPublicEndpointsRequest();
        if (m_peerVersion >= 2)
        {
            std::uint32_t flags = in.ReadUInt32();
            m_dataSavingRequestedByPeer = (flags & INIT_FLAG_DATA_SAVING_ENABLED) == INIT_FLAG_DATA_SAVING_ENABLED;
            UpdateDataSavingState();
            UpdateAudioBitrateLimit();
            ResetEndpointPingStats();
        }
    }
    if (type == PktType::STREAM_EC)
    {
        std::uint8_t streamID = in.ReadUInt8();
        if (m_peerVersion < 7)
        {
            std::uint32_t lastTimestamp = in.ReadUInt32();
            std::uint8_t count = in.ReadUInt8();
            for (std::shared_ptr<Stream>& stm : m_incomingStreams)
            {
                if (stm->id == streamID)
                {
                    for (unsigned int i = 0; i < count; ++i)
                    {
                        std::uint8_t dlen = in.ReadUInt8();
                        std::uint8_t data[256];
                        in.ReadBytes(data, dlen);
                        if (stm->jitterBuffer)
                        {
                            stm->jitterBuffer->HandleInput(data, dlen, lastTimestamp - (count - i - 1) * stm->frameDuration, true);
                        }
                    }
                    break;
                }
            }
        }
        else
        {
            std::shared_ptr<Stream> stm = GetStreamByID(streamID, false);
            if (!stm)
            {
                LOGW("Received FEC packet for unknown stream %u", streamID);
                return;
            }
            if (stm->type != STREAM_TYPE_VIDEO)
            {
                LOGW("Received FEC packet for non-video stream %u", streamID);
                return;
            }
            if (!stm->packetReassembler)
                return;

            std::uint8_t fseq = in.ReadUInt8();
            std::uint8_t fecScheme = in.ReadUInt8();
            std::uint8_t prevFrameCount = in.ReadUInt8();
            std::uint16_t fecLen = in.ReadUInt16();
            if (fecLen > in.Remaining())
                return;

            Buffer fecData(fecLen);
            in.ReadBytes(fecData);

            stm->packetReassembler->AddFEC(std::move(fecData), fseq, prevFrameCount, fecScheme);
        }
    }
}

void VoIPController::ProcessExtraData(Buffer& data)
{
    BufferInputStream in(*data, data.Length());
    std::uint8_t type = in.ReadUInt8();
    std::uint8_t fullHash[SHA1_LENGTH];
    crypto.sha1(*data, data.Length(), fullHash);
    std::uint64_t hash = *reinterpret_cast<std::uint64_t*>(fullHash);
    if (m_lastReceivedExtrasByType[type] == hash)
    {
        return;
    }
    LOGE("ProcessExtraData");
    m_lastReceivedExtrasByType[type] = hash;
    if (type == EXTRA_TYPE_STREAM_FLAGS)
    {
        std::uint8_t id = in.ReadUInt8();
        std::uint32_t flags = in.ReadUInt32();
        LOGV("Peer stream state: id %u flags %u", id, flags);
        for (std::shared_ptr<Stream>& s : m_incomingStreams)
        {
            if (s->id == id)
            {
                bool prevEnabled = s->enabled;
                bool prevPaused = s->paused;
                s->enabled = (flags & STREAM_FLAG_ENABLED) == STREAM_FLAG_ENABLED;
                s->paused = (flags & STREAM_FLAG_PAUSED) == STREAM_FLAG_PAUSED;
                if (flags & STREAM_FLAG_EXTRA_EC)
                {
                    if (!s->extraECEnabled)
                    {
                        s->extraECEnabled = true;
                        if (s->jitterBuffer)
                            s->jitterBuffer->SetMinPacketCount(4);
                    }
                }
                else
                {
                    if (s->extraECEnabled)
                    {
                        s->extraECEnabled = false;
                        if (s->jitterBuffer)
                            s->jitterBuffer->SetMinPacketCount(2);
                    }
                }
                if (prevEnabled != s->enabled && s->type == STREAM_TYPE_VIDEO && m_videoRenderer)
                    m_videoRenderer->SetStreamEnabled(s->enabled);
                if (prevPaused != s->paused && s->type == STREAM_TYPE_VIDEO && m_videoRenderer)
                    m_videoRenderer->SetStreamPaused(s->paused);
                UpdateAudioOutputState();
                break;
            }
        }
    }
    else if (type == EXTRA_TYPE_STREAM_CSD)
    {
        LOGI("Received codec specific data");
        /*
		os.WriteByte(stream.id);
		os.WriteByte(static_cast<unsigned char>(stream.codecSpecificData.size()));
		for(Buffer& b:stream.codecSpecificData){
			assert(b.Length()<255);
			os.WriteByte(static_cast<unsigned char>(b.Length()));
			os.WriteBytes(b);
		}
		Buffer buf(move(os));
		SendExtra(buf, EXTRA_TYPE_STREAM_CSD);
		 */
        std::uint8_t streamID = in.ReadUInt8();
        for (std::shared_ptr<Stream>& stm : m_incomingStreams)
        {
            if (stm->id == streamID)
            {
                stm->codecSpecificData.clear();
                stm->csdIsValid = false;
                stm->width = static_cast<unsigned int>(in.ReadUInt16());
                stm->height = static_cast<unsigned int>(in.ReadUInt16());
                std::size_t count = in.ReadUInt8();
                for (std::size_t i = 0; i < count; i++)
                {
                    std::size_t len = in.ReadUInt8();
                    Buffer csd(len);
                    in.ReadBytes(*csd, len);
                    stm->codecSpecificData.push_back(std::move(csd));
                }
                break;
            }
        }
    }
    else if (type == EXTRA_TYPE_LAN_ENDPOINT)
    {
        if (!m_allowP2p)
            return;
        LOGV("received lan endpoint (extra)");
        std::uint32_t peerAddr = in.ReadUInt32();
        std::uint16_t peerPort = in.ReadUInt16();
        constexpr std::int64_t lanID = static_cast<std::int64_t>(FOURCC('L', 'A', 'N', '4')) << 32;
        if (m_currentEndpoint == lanID)
            m_currentEndpoint = m_preferredRelay;

        std::uint8_t peerTag[16];
        Endpoint lan(lanID, peerPort, NetworkAddress::IPv4(peerAddr), NetworkAddress::Empty(), Endpoint::Type::UDP_P2P_LAN, peerTag);
        MutexGuard m(m_endpointsMutex);
        m_endpoints[lanID] = lan;
    }
    else if (type == EXTRA_TYPE_NETWORK_CHANGED)
    {
        LOGI("Peer network changed");
        m_wasNetworkHandover = true;
        const Endpoint& _currentEndpoint = m_endpoints.at(m_currentEndpoint);
        if (_currentEndpoint.type != Endpoint::Type::UDP_RELAY && _currentEndpoint.type != Endpoint::Type::TCP_RELAY)
            m_currentEndpoint = m_preferredRelay;
        if (m_allowP2p)
            SendPublicEndpointsRequest();
        std::uint32_t flags = in.ReadUInt32();
        m_dataSavingRequestedByPeer = (flags & INIT_FLAG_DATA_SAVING_ENABLED) == INIT_FLAG_DATA_SAVING_ENABLED;
        UpdateDataSavingState();
        UpdateAudioBitrateLimit();
        ResetEndpointPingStats();
    }
    else if (type == EXTRA_TYPE_GROUP_CALL_KEY)
    {
        if (!m_didReceiveGroupCallKey && !m_didSendGroupCallKey)
        {
            std::uint8_t groupKey[256];
            in.ReadBytes(groupKey, 256);
            m_messageThread.Post([this, &groupKey] {
                if (m_callbacks.groupCallKeyReceived)
                    m_callbacks.groupCallKeyReceived(this, groupKey);
            });
            m_didReceiveGroupCallKey = true;
        }
    }
    else if (type == EXTRA_TYPE_REQUEST_GROUP)
    {
        if (!m_didInvokeUpgradeCallback)
        {
            m_messageThread.Post([this] {
                if (m_callbacks.upgradeToGroupCallRequested)
                    m_callbacks.upgradeToGroupCallRequested(this);
            });
            m_didInvokeUpgradeCallback = true;
        }
    }
    else if (type == EXTRA_TYPE_IPV6_ENDPOINT)
    {
        if (!m_allowP2p)
            return;
        std::uint8_t _addr[16];
        in.ReadBytes(_addr, 16);
        NetworkAddress addr = NetworkAddress::IPv6(_addr);
        std::uint16_t port = in.ReadUInt16();
        m_peerIPv6Available = true;
        LOGV("Received peer IPv6 endpoint [%s]:%u", addr.ToString().c_str(), port);

        constexpr std::int64_t p2pID = static_cast<std::int64_t>(FOURCC('P', '2', 'P', '6')) << 32;

        Endpoint ep;
        ep.type = Endpoint::Type::UDP_P2P_INET;
        ep.port = port;
        ep.v6address = addr;
        ep.id = p2pID;
        m_endpoints[p2pID] = ep;
        if (!m_myIPv6.IsEmpty())
            m_currentEndpoint = p2pID;
    }
}

void VoIPController::ProcessAcknowledgedOutgoingExtra(UnacknowledgedExtraData& extra)
{
    if (extra.type == EXTRA_TYPE_GROUP_CALL_KEY)
    {
        if (!m_didReceiveGroupCallKeyAck)
        {
            m_didReceiveGroupCallKeyAck = true;
            m_messageThread.Post([this] {
                if (m_callbacks.groupCallKeySent)
                    m_callbacks.groupCallKeySent(this);
            });
        }
    }
}

Endpoint& VoIPController::GetRemoteEndpoint()
{
    return m_endpoints.at(m_currentEndpoint);
}

Endpoint* VoIPController::GetEndpointForPacket(const PendingOutgoingPacket& pkt)
{
    Endpoint* endpoint = nullptr;
    if (pkt.endpoint)
    {
        try
        {
            endpoint = &m_endpoints.at(pkt.endpoint);
        }
        catch (const std::out_of_range& x)
        {
            LOGW("Unable to send packet via nonexistent endpoint %" PRIu64 "\ne.what(): %s", pkt.endpoint, x.what());
            return nullptr;
        }
    }
    if (!endpoint)
        endpoint = &m_endpoints.at(m_currentEndpoint);
    return endpoint;
}

bool VoIPController::SendOrEnqueuePacket(PendingOutgoingPacket pkt, bool enqueue, PacketSender* source)
{
    ENFORCE_MSG_THREAD;

    Endpoint* endpoint = GetEndpointForPacket(pkt);
    if (!endpoint)
    {
        abort();
        return false;
    }

    bool canSend;
    if (endpoint->type != Endpoint::Type::TCP_RELAY)
    {
        canSend = m_realUdpSocket->IsReadyToSend();
    }
    else
    {
        if (!endpoint->m_socket)
        {
            LOGV("Connecting to %s:%u", endpoint->GetAddress().ToString().c_str(), endpoint->port);
            if (m_proxyProtocol == Proxy::NONE)
            {
                endpoint->m_socket = std::make_shared<NetworkSocketTCPObfuscated>(NetworkSocket::Create(NetworkProtocol::TCP));
                endpoint->m_socket->Connect(endpoint->GetAddress(), endpoint->port);
            }
            else if (m_proxyProtocol == Proxy::SOCKS5)
            {
                NetworkSocket* tcp = NetworkSocket::Create(NetworkProtocol::TCP);
                tcp->Connect(m_resolvedProxyAddress, m_proxyPort);
                std::shared_ptr<NetworkSocketSOCKS5Proxy> proxy = std::make_shared<NetworkSocketSOCKS5Proxy>(tcp, nullptr, m_proxyUsername, m_proxyPassword);
                endpoint->m_socket = proxy;
                endpoint->m_socket->Connect(endpoint->GetAddress(), endpoint->port);
            }
            m_selectCanceller->CancelSelect();
        }
        canSend = endpoint->m_socket && endpoint->m_socket->IsReadyToSend();
    }
    if (!canSend)
    {
        if (enqueue)
        {
            LOGW("Not ready to send - enqueueing");
            m_sendQueue.push_back(std::move(pkt));
        }
        return false;
    }
    if ((endpoint->type == Endpoint::Type::TCP_RELAY && m_useTCP) || (endpoint->type != Endpoint::Type::TCP_RELAY && m_useUDP))
    {
        //BufferOutputStream p(buf, sizeof(buf));
        BufferOutputStream p(1500);
        WritePacketHeader(pkt.seq, &p, pkt.type, static_cast<std::uint32_t>(pkt.len), source);
        p.WriteBytes(pkt.data);
        SendPacket(p.GetBuffer(), p.GetLength(), *endpoint, pkt);
        if (pkt.type == PktType::STREAM_DATA)
        {
            m_unsentStreamPackets--;
        }
    }
    return true;
}

void VoIPController::SendPacket(std::uint8_t* data, std::size_t len, Endpoint& ep, PendingOutgoingPacket& srcPacket)
{
    if (m_stopping)
        return;
    if (ep.type == Endpoint::Type::TCP_RELAY && !m_useTCP)
        return;
    BufferOutputStream out(len + 128);
    if (ep.type == Endpoint::Type::UDP_RELAY || ep.type == Endpoint::Type::TCP_RELAY)
        out.WriteBytes(ep.peerTag, 16);
    else if (m_peerVersion < 9)
        out.WriteBytes(m_callID, 16);
    if (len > 0)
    {
        if (m_useMTProto2)
        {
            BufferOutputStream inner(len + 128);
            std::size_t sizeSize;
            if (m_peerVersion >= 8 || (!m_peerVersion && m_connectionMaxLayer >= 92))
            {
                inner.WriteUInt16(static_cast<std::uint16_t>(len));
                sizeSize = 0;
            }
            else
            {
                inner.WriteUInt32(static_cast<std::uint32_t>(len));
                out.WriteBytes(m_keyFingerprint, 8);
                sizeSize = 4;
            }
            inner.WriteBytes(data, len);

            std::size_t padLen = 16 - inner.GetLength() % 16;
            if (padLen < 16)
                padLen += 16;
            std::uint8_t padding[32];
            crypto.rand_bytes(padding, padLen);
            inner.WriteBytes(padding, padLen);
            assert(inner.GetLength() % 16 == 0);

            std::uint8_t key[32], iv[32], msgKey[16];
            BufferOutputStream buf(len + 32);
            std::size_t x = m_isOutgoing ? 0 : 8;
            buf.WriteBytes(m_encryptionKey + 88 + x, 32);
            buf.WriteBytes(inner.GetBuffer() + sizeSize, inner.GetLength() - sizeSize);
            std::uint8_t msgKeyLarge[32];
            crypto.sha256(buf.GetBuffer(), buf.GetLength(), msgKeyLarge);
            std::memcpy(msgKey, msgKeyLarge + 8, 16);
            KDF2(msgKey, m_isOutgoing ? 0 : 8, key, iv);
            out.WriteBytes(msgKey, 16);
            //LOGV("<- MSG KEY: %08x %08x %08x %08x, hashed %u", *reinterpret_cast<std::int32_t*>(msgKey), *reinterpret_cast<std::int32_t*>(msgKey+4), *reinterpret_cast<std::int32_t*>(msgKey+8), *reinterpret_cast<std::int32_t*>(msgKey+12), inner.GetLength()-4);

            std::uint8_t aesOut[MSC_STACK_FALLBACK(inner.GetLength(), 1500)];
            crypto.aes_ige_encrypt(inner.GetBuffer(), aesOut, inner.GetLength(), key, iv);
            out.WriteBytes(aesOut, inner.GetLength());
        }
        else
        {
            BufferOutputStream inner(len + 128);
            inner.WriteUInt32(static_cast<std::uint32_t>(len));
            inner.WriteBytes(data, len);
            if (inner.GetLength() % 16 != 0)
            {
                std::size_t padLen = 16 - inner.GetLength() % 16;
                std::uint8_t padding[16];
                crypto.rand_bytes(padding, padLen);
                inner.WriteBytes(padding, padLen);
            }
            assert(inner.GetLength() % 16 == 0);
            std::uint8_t key[32], iv[32], msgHash[SHA1_LENGTH];
            crypto.sha1(inner.GetBuffer(), len + 4, msgHash);
            out.WriteBytes(m_keyFingerprint, 8);
            out.WriteBytes((msgHash + (SHA1_LENGTH - 16)), 16);
            KDF(msgHash + (SHA1_LENGTH - 16), m_isOutgoing ? 0 : 8, key, iv);
            std::vector<std::uint8_t> aesOut(MSC_STACK_FALLBACK(inner.GetLength(), 1500));
            crypto.aes_ige_encrypt(inner.GetBuffer(), aesOut.data(), inner.GetLength(), key, iv);
            out.WriteBytes(aesOut.data(), inner.GetLength());
        }
    }
    //LOGV("Sending %d bytes to %s:%d", out.GetLength(), ep.address.ToString().c_str(), ep.port);
#ifdef LOG_PACKETS
    LOGV("Sending: to=%s:%u, seq=%u, length=%u, type=%s", ep.GetAddress().ToString().c_str(), ep.port, srcPacket.seq, (unsigned int)out.GetLength(), GetPacketTypeString(srcPacket.type).c_str());
#endif

    /*ActuallySendPacket(NetworkPacket{
			Buffer(std::move(out)),
			ep.GetAddress(),
			ep.port,
			ep.type==Endpoint::Type::TCP_RELAY ? NetworkProtocol::TCP : NetworkProtocol::UDP
		}, ep);*/
    m_rawSendQueue.Put(RawPendingOutgoingPacket
    {
        NetworkPacket
        {
            Buffer(std::move(out)),
            ep.GetAddress(),
            ep.port,
            ep.type == Endpoint::Type::TCP_RELAY ? NetworkProtocol::TCP : NetworkProtocol::UDP
        },
        ep.type == Endpoint::Type::TCP_RELAY ? ep.m_socket : nullptr
    });
}

void VoIPController::ActuallySendPacket(NetworkPacket pkt, Endpoint& ep)
{
    //LOGI("Sending packet of %d bytes", pkt.length);
    if (IS_MOBILE_NETWORK(m_networkType))
        m_stats.bytesSentMobile += static_cast<std::uint64_t>(pkt.data.Length());
    else
        m_stats.bytesSentWifi += static_cast<std::uint64_t>(pkt.data.Length());
    if (ep.type == Endpoint::Type::TCP_RELAY)
    {
        if (ep.m_socket && !ep.m_socket->IsFailed())
        {
            ep.m_socket->Send(std::move(pkt));
        }
    }
    else
    {
        m_udpSocket->Send(std::move(pkt));
    }
}

std::string VoIPController::NetworkTypeToString(NetType type)
{
    switch (type)
    {
    case NetType::WIFI:
        return "wifi";
    case NetType::GPRS:
        return "gprs";
    case NetType::EDGE:
        return "edge";
    case NetType::THREE_G:
        return "3g";
    case NetType::HSPA:
        return "hspa";
    case NetType::LTE:
        return "lte";
    case NetType::ETHERNET:
        return "ethernet";
    case NetType::OTHER_HIGH_SPEED:
        return "other_high_speed";
    case NetType::OTHER_LOW_SPEED:
        return "other_low_speed";
    case NetType::DIALUP:
        return "dialup";
    case NetType::OTHER_MOBILE:
        return "other_mobile";
    default:
        return "unknown";
    }
}

std::string VoIPController::GetPacketTypeString(PktType type)
{
    switch (type)
    {
    case PktType::INIT:
        return "init";
    case PktType::INIT_ACK:
        return "init_ack";
    case PktType::STREAM_STATE:
        return "stream_state";
    case PktType::STREAM_DATA:
        return "stream_data";
    case PktType::PING:
        return "ping";
    case PktType::PONG:
        return "pong";
    case PktType::LAN_ENDPOINT:
        return "lan_endpoint";
    case PktType::NETWORK_CHANGED:
        return "network_changed";
    case PktType::NOP:
        return "nop";
    case PktType::STREAM_EC:
        return "stream_ec";
    case PktType::UPDATE_STREAMS:
        return "update_streams";
    case PktType::STREAM_DATA_X2:
        return "stream_data_x2";
    case PktType::STREAM_DATA_X3:
        return "stream_data_x3";
    case PktType::SWITCH_PREF_RELAY:
        return "switch_pref_relay";
    case PktType::SWITCH_TO_P2P:
        return "switch_to_p2p";
    }
    return std::string("unknown " + std::to_string(static_cast<std::uint8_t>(type)));
}

void VoIPController::AddIPv6Relays()
{
    if (!m_myIPv6.IsEmpty() && !m_didAddIPv6Relays)
    {
        std::unordered_map<std::string, std::vector<Endpoint>> endpointsByAddress;
        for (std::pair<const std::int64_t, Endpoint>& _e : m_endpoints)
        {
            Endpoint& e = _e.second;
            if ((e.type == Endpoint::Type::UDP_RELAY || e.type == Endpoint::Type::TCP_RELAY) && !e.v6address.IsEmpty() && !e.address.IsEmpty())
            {
                endpointsByAddress[e.v6address.ToString()].push_back(e);
            }
        }
        MutexGuard m(m_endpointsMutex);
        for (std::pair<const std::string, std::vector<Endpoint>>& addr : endpointsByAddress)
        {
            for (Endpoint& e : addr.second)
            {
                m_didAddIPv6Relays = true;
                e.address = NetworkAddress::Empty();
                e.id = e.id ^ (static_cast<std::int64_t>(FOURCC('I', 'P', 'v', '6')) << 32);
                e.m_averageRTT = 0;
                e.m_lastPingSeq = 0;
                e.m_lastPingTime = 0;
                e.m_rtts.Reset();
                e.m_udpPongCount = 0;
                m_endpoints[e.id] = e;
                LOGD("Adding IPv6-only endpoint [%s]:%u", e.v6address.ToString().c_str(), e.port);
            }
        }
    }
}

void VoIPController::AddTCPRelays()
{

    if (!m_didAddTcpRelays)
    {
        bool wasSetCurrentToTCP = m_setCurrentEndpointToTCP;
        LOGV("Adding TCP relays");
        std::vector<Endpoint> relays;
        for (std::pair<const std::int64_t, Endpoint>& _e : m_endpoints)
        {
            Endpoint& e = _e.second;
            if (e.type != Endpoint::Type::UDP_RELAY)
                continue;
            if (wasSetCurrentToTCP && !m_useUDP)
            {
                e.m_rtts.Reset();
                e.m_averageRTT = 0;
                e.m_lastPingSeq = 0;
            }
            Endpoint tcpRelay(e);
            tcpRelay.type = Endpoint::Type::TCP_RELAY;
            tcpRelay.m_averageRTT = 0;
            tcpRelay.m_lastPingSeq = 0;
            tcpRelay.m_lastPingTime = 0;
            tcpRelay.m_rtts.Reset();
            tcpRelay.m_udpPongCount = 0;
            tcpRelay.id = tcpRelay.id ^ (static_cast<std::int64_t>(FOURCC('T', 'C', 'P', 0)) << 32);
            if (m_setCurrentEndpointToTCP && m_endpoints.at(m_currentEndpoint).type != Endpoint::Type::TCP_RELAY)
            {
                LOGV("Setting current endpoint to TCP");
                m_setCurrentEndpointToTCP = false;
                m_currentEndpoint = tcpRelay.id;
                m_preferredRelay = tcpRelay.id;
            }
            relays.push_back(tcpRelay);
        }
        MutexGuard m(m_endpointsMutex);
        for (Endpoint& e : relays)
        {
            m_endpoints[e.id] = e;
        }
        m_didAddTcpRelays = true;
    }
}

#if defined(__APPLE__)
static void initMachTimestart()
{
    mach_timebase_info_data_t tb = {0, 0};
    mach_timebase_info(&tb);
    VoIPController::machTimebase = tb.numer;
    VoIPController::machTimebase /= tb.denom;
    VoIPController::machTimestart = mach_absolute_time();
}
#endif

double VoIPController::GetCurrentTime()
{
#if defined(__linux__)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1000000000.0;
#elif defined(__APPLE__)
    static pthread_once_t token = PTHREAD_ONCE_INIT;
    pthread_once(&token, &initMachTimestart);
    return (mach_absolute_time() - machTimestart) * machTimebase / 1000000000.0f;
#elif defined(_WIN32)
    if (!didInitWin32TimeScale)
    {
        LARGE_INTEGER scale;
        QueryPerformanceFrequency(&scale);
        win32TimeScale = scale.QuadPart;
        didInitWin32TimeScale = true;
    }
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / (double)win32TimeScale;
#endif
}

void VoIPController::KDF(std::uint8_t* msgKey, std::size_t x, std::uint8_t* aesKey, std::uint8_t* aesIv)
{
    std::uint8_t sA[SHA1_LENGTH], sB[SHA1_LENGTH], sC[SHA1_LENGTH], sD[SHA1_LENGTH];
    BufferOutputStream buf(128);
    buf.WriteBytes(msgKey, 16);
    buf.WriteBytes(m_encryptionKey + x, 32);
    crypto.sha1(buf.GetBuffer(), buf.GetLength(), sA);
    buf.Reset();
    buf.WriteBytes(m_encryptionKey + 32 + x, 16);
    buf.WriteBytes(msgKey, 16);
    buf.WriteBytes(m_encryptionKey + 48 + x, 16);
    crypto.sha1(buf.GetBuffer(), buf.GetLength(), sB);
    buf.Reset();
    buf.WriteBytes(m_encryptionKey + 64 + x, 32);
    buf.WriteBytes(msgKey, 16);
    crypto.sha1(buf.GetBuffer(), buf.GetLength(), sC);
    buf.Reset();
    buf.WriteBytes(msgKey, 16);
    buf.WriteBytes(m_encryptionKey + 96 + x, 32);
    crypto.sha1(buf.GetBuffer(), buf.GetLength(), sD);
    buf.Reset();
    buf.WriteBytes(sA, 8);
    buf.WriteBytes(sB + 8, 12);
    buf.WriteBytes(sC + 4, 12);
    assert(buf.GetLength() == 32);
    std::memcpy(aesKey, buf.GetBuffer(), 32);
    buf.Reset();
    buf.WriteBytes(sA + 8, 12);
    buf.WriteBytes(sB, 8);
    buf.WriteBytes(sC + 16, 4);
    buf.WriteBytes(sD, 8);
    assert(buf.GetLength() == 32);
    std::memcpy(aesIv, buf.GetBuffer(), 32);
}

void VoIPController::KDF2(std::uint8_t* msgKey, std::size_t x, std::uint8_t* aesKey, std::uint8_t* aesIv)
{
    std::uint8_t sA[32], sB[32];
    BufferOutputStream buf(128);
    buf.WriteBytes(msgKey, 16);
    buf.WriteBytes(m_encryptionKey + x, 36);
    crypto.sha256(buf.GetBuffer(), buf.GetLength(), sA);
    buf.Reset();
    buf.WriteBytes(m_encryptionKey + 40 + x, 36);
    buf.WriteBytes(msgKey, 16);
    crypto.sha256(buf.GetBuffer(), buf.GetLength(), sB);
    buf.Reset();
    buf.WriteBytes(sA, 8);
    buf.WriteBytes(sB + 8, 16);
    buf.WriteBytes(sA + 24, 8);
    std::memcpy(aesKey, buf.GetBuffer(), 32);
    buf.Reset();
    buf.WriteBytes(sB, 8);
    buf.WriteBytes(sA + 8, 16);
    buf.WriteBytes(sB + 24, 8);
    std::memcpy(aesIv, buf.GetBuffer(), 32);
}

void VoIPController::SendPublicEndpointsRequest(const Endpoint& relay)
{
    if (!m_useUDP)
        return;
    LOGD("Sending public endpoints request to %s:%d", relay.address.ToString().c_str(), relay.port);
    m_publicEndpointsReqTime = GetCurrentTime();
    m_waitingForRelayPeerInfo = true;
    Buffer buf(32);
    std::memcpy(*buf, relay.peerTag, 16);
    std::memset(*buf + 16, 0xFF, 16);
    m_udpSocket->Send(NetworkPacket
    {
        std::move(buf),
        relay.address,
        relay.port,
        NetworkProtocol::UDP
    });
}

Endpoint& VoIPController::GetEndpointByType(Endpoint::Type type)
{
    if (type == Endpoint::Type::UDP_RELAY && m_preferredRelay)
        return m_endpoints.at(m_preferredRelay);
    for (std::pair<const std::int64_t, Endpoint>& e : m_endpoints)
    {
        if (e.second.type == type)
            return e.second;
    }
    throw std::out_of_range("no endpoint");
}

void VoIPController::SendPacketReliably(PktType type, std::uint8_t* data, std::size_t len, double retryInterval, double timeout)
{
    ENFORCE_MSG_THREAD;

    LOGD("Send reliably, type=%u, len=%u, retry=%.3f, timeout=%.3f", static_cast<std::uint8_t>(type), unsigned(len), retryInterval, timeout);
    QueuedPacket pkt;
    if (data)
    {
        Buffer b(len);
        b.CopyFrom(data, 0, len);
        pkt.data = std::move(b);
    }
    pkt.type = type;
    pkt.retryInterval = retryInterval;
    pkt.timeout = timeout;
    pkt.firstSentTime = 0;
    pkt.lastSentTime = 0;
    m_queuedPackets.push_back(std::move(pkt));
    m_messageThread.Post(std::bind(&VoIPController::UpdateQueuedPackets, this));
    if (timeout > 0.0)
    {
        m_messageThread.Post(std::bind(&VoIPController::UpdateQueuedPackets, this), timeout);
    }
}

void VoIPController::SendExtra(Buffer& data, std::uint8_t type)
{
    ENFORCE_MSG_THREAD;

    LOGV("Sending extra type %u length %u", type, static_cast<unsigned int>(data.Length()));
    for (std::vector<UnacknowledgedExtraData>::iterator x = m_currentExtras.begin(); x != m_currentExtras.end(); ++x)
    {
        if (x->type == type)
        {
            x->firstContainingSeq = 0;
            x->data = std::move(data);
            return;
        }
    }
    UnacknowledgedExtraData xd = {type, std::move(data), 0};
    m_currentExtras.push_back(std::move(xd));
}

void VoIPController::DebugCtl(int request, int param)
{
}

void VoIPController::SendUdpPing(Endpoint& endpoint)
{
    if (endpoint.type != Endpoint::Type::UDP_RELAY)
        return;
    BufferOutputStream p(1024);
    p.WriteBytes(endpoint.peerTag, 16);
    p.WriteInt32(-1);
    p.WriteInt32(-1);
    p.WriteInt32(-1);
    p.WriteInt32(-2);
    std::int64_t id;
    crypto.rand_bytes(reinterpret_cast<std::uint8_t*>(&id), 8);
    p.WriteInt64(id);
    endpoint.m_udpPingTimes[id] = GetCurrentTime();
    m_udpSocket->Send(NetworkPacket {
        Buffer(std::move(p)),
        endpoint.GetAddress(),
        endpoint.port,
        NetworkProtocol::UDP});
    endpoint.m_totalUdpPings++;
    LOGV("Sending UDP ping to %s:%d, id %" PRId64, endpoint.GetAddress().ToString().c_str(), endpoint.port, id);
}

void VoIPController::ResetUdpAvailability()
{
    ENFORCE_MSG_THREAD;

    LOGI("Resetting UDP availability");
    if (m_udpPingTimeoutID != MessageThread::INVALID_ID)
    {
        m_messageThread.Cancel(m_udpPingTimeoutID);
    }
    {
        for (std::pair<const std::int64_t, Endpoint>& e : m_endpoints)
        {
            e.second.m_udpPongCount = 0;
            e.second.m_udpPingTimes.clear();
        }
    }
    m_udpPingCount = 0;
    m_udpConnectivityState = UdpState::PING_PENDING;
    m_udpPingTimeoutID = m_messageThread.Post(std::bind(&VoIPController::SendUdpPings, this), 0.0, 0.5);
}

void VoIPController::ResetEndpointPingStats()
{
    ENFORCE_MSG_THREAD;

    for (std::pair<const std::int64_t, Endpoint>& e : m_endpoints)
    {
        e.second.m_averageRTT = 0.0;
        e.second.m_rtts.Reset();
    }
}

#pragma mark - Video

void VoIPController::SetVideoSource(video::VideoSource* source)
{
    std::shared_ptr<Stream> stm = GetStreamByType(STREAM_TYPE_VIDEO, true);
    if (!stm)
    {
        LOGE("Can't set video source when there is no outgoing video stream");
        return;
    }

    if (source)
    {
        if (!stm->enabled)
        {
            stm->enabled = true;
            m_messageThread.Post([this, stm] { SendStreamFlags(*stm); });
        }

        if (!m_videoPacketSender)
            m_videoPacketSender = new video::VideoPacketSender(this, source, stm);
        else
            m_videoPacketSender->SetSource(source);
    }
    else
    {
        if (stm->enabled)
        {
            stm->enabled = false;
            m_messageThread.Post([this, stm] { SendStreamFlags(*stm); });
        }
        if (m_videoPacketSender)
        {
            m_videoPacketSender->SetSource(nullptr);
        }
    }
}

void VoIPController::SetVideoRenderer(video::VideoRenderer* renderer)
{
    m_videoRenderer = renderer;
}

void VoIPController::SetVideoCodecSpecificData(const std::vector<Buffer>& data)
{
    m_outgoingStreams[1]->codecSpecificData.clear();
    for (const Buffer& csd : data)
    {
        m_outgoingStreams[1]->codecSpecificData.push_back(Buffer::CopyOf(csd));
    }
    LOGI("Set outgoing video stream CSD");
}

void VoIPController::SendVideoFrame(const Buffer& frame, std::uint32_t flags, std::uint32_t rotation)
{
    //LOGI("Send video frame %u flags %u", (unsigned int)frame.Length(), flags);
    std::shared_ptr<Stream> stm = GetStreamByType(STREAM_TYPE_VIDEO, true);
    if (stm)
    {
    }
}

void VoIPController::ProcessIncomingVideoFrame(Buffer frame, std::uint32_t pts, bool keyframe, std::uint16_t rotation)
{
    //LOGI("Incoming video frame size %u pts %u", (unsigned int)frame.Length(), pts);
    if (frame.Length() == 0)
    {
        LOGE("EMPTY FRAME");
    }
    if (m_videoRenderer)
    {
        std::shared_ptr<Stream> stm = GetStreamByType(STREAM_TYPE_VIDEO, false);
        std::size_t offset = 0;
        if (keyframe)
        {
            BufferInputStream in(frame);
            std::uint16_t width = in.ReadUInt16();
            std::uint16_t height = in.ReadUInt16();
            std::uint8_t sizeAndFlag = in.ReadUInt8();
            int size = sizeAndFlag & 0x0F;
            bool reset = (sizeAndFlag & 0x80) == 0x80;
            if (reset || !stm->csdIsValid || stm->width != width || stm->height != height)
            {
                stm->width = width;
                stm->height = height;
                stm->codecSpecificData.clear();
                for (int i = 0; i < size; i++)
                {
                    std::size_t len = in.ReadUInt8();
                    Buffer b(len);
                    in.ReadBytes(b);
                    stm->codecSpecificData.push_back(std::move(b));
                }
                stm->csdIsValid = false;
            }
            else
            {
                for (int i = 0; i < size; i++)
                {
                    std::size_t len = in.ReadUInt8();
                    in.Seek(in.GetOffset() + len);
                }
            }
            offset = in.GetOffset();
        }
        if (!stm->csdIsValid && stm->width && stm->height)
        {
            m_videoRenderer->Reset(stm->codec, stm->width, stm->height, stm->codecSpecificData);
            stm->csdIsValid = true;
        }
        if (m_lastReceivedVideoFrameNumber == UINT32_MAX || m_lastReceivedVideoFrameNumber == pts - 1 || keyframe)
        {
            m_lastReceivedVideoFrameNumber = pts;
            //LOGV("3 before decode %u", (unsigned int)frame.Length());
            if (stm->rotation != rotation)
            {
                stm->rotation = rotation;
                m_videoRenderer->SetRotation(rotation);
            }
            if (offset == 0)
            {
                m_videoRenderer->DecodeAndDisplay(std::move(frame), pts);
            }
            else
            {
                m_videoRenderer->DecodeAndDisplay(Buffer::CopyOf(frame, offset, frame.Length() - offset), pts);
            }
        }
        else
        {
            LOGW("Skipping non-keyframe after packet loss...");
        }
    }
}

void VoIPController::SetupOutgoingVideoStream()
{
    std::vector<std::uint32_t> myEncoders = video::VideoSource::GetAvailableEncoders();
    std::shared_ptr<Stream> vstm = std::make_shared<Stream>();
    vstm->id = 2;
    vstm->type = STREAM_TYPE_VIDEO;

    if (find(myEncoders.begin(), myEncoders.end(), CODEC_HEVC) != myEncoders.end() && find(m_peerVideoDecoders.begin(), m_peerVideoDecoders.end(), CODEC_HEVC) != m_peerVideoDecoders.end())
    {
        vstm->codec = CODEC_HEVC;
    }
    else if (find(myEncoders.begin(), myEncoders.end(), CODEC_AVC) != myEncoders.end() && find(m_peerVideoDecoders.begin(), m_peerVideoDecoders.end(), CODEC_AVC) != m_peerVideoDecoders.end())
    {
        vstm->codec = CODEC_AVC;
    }
    else if (find(myEncoders.begin(), myEncoders.end(), CODEC_VP8) != myEncoders.end() && find(m_peerVideoDecoders.begin(), m_peerVideoDecoders.end(), CODEC_VP8) != m_peerVideoDecoders.end())
    {
        vstm->codec = CODEC_VP8;
    }
    else
    {
        LOGW("Can't setup outgoing video stream: no codecs in common");
        return;
    }

    vstm->enabled = false;
    m_outgoingStreams.push_back(vstm);
}

#pragma mark - Timer methods

void VoIPController::SendUdpPings()
{
    LOGW("Send udp pings");
    ENFORCE_MSG_THREAD;

    for (std::pair<const std::int64_t, Endpoint>& e : m_endpoints)
    {
        if (e.second.type == Endpoint::Type::UDP_RELAY)
        {
            SendUdpPing(e.second);
        }
    }
    if (m_udpConnectivityState == UdpState::UNKNOWN || m_udpConnectivityState == UdpState::PING_PENDING)
        m_udpConnectivityState = UdpState::PING_SENT;
    m_udpPingCount++;
    if (m_udpPingCount == 4 || m_udpPingCount == 10)
    {
        m_messageThread.CancelSelf();
        m_udpPingTimeoutID = m_messageThread.Post(std::bind(&VoIPController::EvaluateUdpPingResults, this), 1.0);
    }
}

void VoIPController::EvaluateUdpPingResults()
{
    double avgPongs = 0;
    int count = 0;
    for (std::pair<const std::int64_t, Endpoint>& _e : m_endpoints)
    {
        Endpoint& e = _e.second;
        if (e.type == Endpoint::Type::UDP_RELAY)
        {
            if (e.m_udpPongCount > 0)
            {
                avgPongs += e.m_udpPongCount;
                count++;
            }
        }
    }
    if (count > 0)
        avgPongs /= count;
    else
        avgPongs = 0.0;
    LOGI("UDP ping reply count: %.2f", avgPongs);
    if (avgPongs == 0.0 && m_proxyProtocol == Proxy::SOCKS5 && m_udpSocket != m_realUdpSocket)
    {
        LOGI("Proxy does not let UDP through, closing proxy connection and using UDP directly");
        NetworkSocket* proxySocket = m_udpSocket;
        proxySocket->Close();
        m_udpSocket = m_realUdpSocket;
        m_selectCanceller->CancelSelect();
        delete proxySocket;
        m_proxySupportsUDP = false;
        ResetUdpAvailability();
        return;
    }
    bool configUseTCP = ServerConfig::GetSharedInstance()->GetBoolean("use_tcp", true);
    if (configUseTCP)
    {
        if (avgPongs == 0.0 || (m_udpConnectivityState == UdpState::BAD && avgPongs < 7.0))
        {
            if (m_needRateFlags & NEED_RATE_FLAG_UDP_NA)
                m_needRate = true;
            m_udpConnectivityState = UdpState::NOT_AVAILABLE;
            m_useTCP = true;
            m_useUDP = avgPongs > 1.0;
            if (m_endpoints.at(m_currentEndpoint).type != Endpoint::Type::TCP_RELAY)
                m_setCurrentEndpointToTCP = true;
            AddTCPRelays();
            m_waitingForRelayPeerInfo = false;
        }
        else if (avgPongs < 3.0)
        {
            if (m_needRateFlags & NEED_RATE_FLAG_UDP_BAD)
                m_needRate = true;
            m_udpConnectivityState = UdpState::BAD;
            m_useTCP = true;
            m_setCurrentEndpointToTCP = true;
            AddTCPRelays();
            m_udpPingTimeoutID = m_messageThread.Post(std::bind(&VoIPController::SendUdpPings, this), 0.5, 0.5);
        }
        else
        {
            m_udpPingTimeoutID = MessageThread::INVALID_ID;
            m_udpConnectivityState = UdpState::AVAILABLE;
        }
    }
    else
    {
        m_udpPingTimeoutID = MessageThread::INVALID_ID;
        m_udpConnectivityState = UdpState::NOT_AVAILABLE;
    }
}

void VoIPController::SendRelayPings()
{
    ENFORCE_MSG_THREAD;

    if ((m_state == State::ESTABLISHED || m_state == State::RECONNECTING) && m_endpoints.size() > 1)
    {
        Endpoint* _preferredRelay = &m_endpoints.at(m_preferredRelay);
        Endpoint* _currentEndpoint = &m_endpoints.at(m_currentEndpoint);
        Endpoint* minPingRelay = _preferredRelay;
        double minPing = _preferredRelay->m_averageRTT * (_preferredRelay->type == Endpoint::Type::TCP_RELAY ? 2 : 1);
        if (minPing == 0.0) // force the switch to an available relay, if any
            minPing = DBL_MAX;
        for (std::pair<const std::int64_t, Endpoint>& _endpoint : m_endpoints)
        {
            Endpoint& endpoint = _endpoint.second;
            if (endpoint.type == Endpoint::Type::TCP_RELAY && !m_useTCP)
                continue;
            if (endpoint.type == Endpoint::Type::UDP_RELAY && !m_useUDP)
                continue;
            if (GetCurrentTime() - endpoint.m_lastPingTime >= 10)
            {
                LOGV("Sending ping to %s", endpoint.GetAddress().ToString().c_str());
                SendOrEnqueuePacket(PendingOutgoingPacket {
                    /*.seq=*/(endpoint.m_lastPingSeq = GenerateOutSeq()),
                    /*.type=*/PktType::PING,
                    /*.len=*/0,
                    /*.data=*/Buffer(),
                    /*.endpoint=*/endpoint.id});
                endpoint.m_lastPingTime = GetCurrentTime();
            }
            if ((m_useUDP && endpoint.type == Endpoint::Type::UDP_RELAY) || (m_useTCP && endpoint.type == Endpoint::Type::TCP_RELAY))
            {
                double k = endpoint.type == Endpoint::Type::UDP_RELAY ? 1 : 2;
                if (endpoint.m_averageRTT > 0 && endpoint.m_averageRTT * k < minPing * m_relaySwitchThreshold)
                {
                    minPing = endpoint.m_averageRTT * k;
                    minPingRelay = &endpoint;
                }
            }
        }
        if (minPingRelay->id != m_preferredRelay)
        {
            m_preferredRelay = minPingRelay->id;
            _preferredRelay = minPingRelay;
            LOGV("set preferred relay to %s", _preferredRelay->address.ToString().c_str());
            if (_currentEndpoint->type == Endpoint::Type::UDP_RELAY || _currentEndpoint->type == Endpoint::Type::TCP_RELAY)
            {
                m_currentEndpoint = m_preferredRelay;
                _currentEndpoint = _preferredRelay;
            }
        }
        if (_currentEndpoint->type == Endpoint::Type::UDP_RELAY && m_useUDP)
        {
            constexpr std::int64_t p2pID = static_cast<std::int64_t>(FOURCC('P', '2', 'P', '4')) << 32;
            constexpr std::int64_t lanID = static_cast<std::int64_t>(FOURCC('L', 'A', 'N', '4')) << 32;

            if (m_endpoints.find(p2pID) != m_endpoints.end())
            {
                Endpoint& p2p = m_endpoints[p2pID];
                if (m_endpoints.find(lanID) != m_endpoints.end() && m_endpoints[lanID].m_averageRTT > 0 && m_endpoints[lanID].m_averageRTT < minPing * m_relayToP2pSwitchThreshold)
                {
                    m_currentEndpoint = lanID;
                    LOGI("Switching to p2p (LAN)");
                }
                else
                {
                    if (p2p.m_averageRTT > 0 && p2p.m_averageRTT < minPing * m_relayToP2pSwitchThreshold)
                    {
                        m_currentEndpoint = p2pID;
                        LOGI("Switching to p2p (Inet)");
                    }
                }
            }
        }
        else
        {
            if (minPing > 0 && minPing < _currentEndpoint->m_averageRTT * m_p2pToRelaySwitchThreshold)
            {
                LOGI("Switching to relay");
                m_currentEndpoint = m_preferredRelay;
            }
        }
    }
}

void VoIPController::UpdateRTT()
{
    m_rttHistory.Add(GetAverageRTT());
    //double v=rttHistory.Average();
    if (m_rttHistory[0] > 10.0 && m_rttHistory[8] > 10.0 && (m_networkType == NetType::EDGE || m_networkType == NetType::GPRS))
    {
        m_waitingForAcks = true;
    }
    else
    {
        m_waitingForAcks = false;
    }
    //LOGI("%.3lf/%.3lf, rtt diff %.3lf, waiting=%d, queue=%d", rttHistory[0], rttHistory[8], v, waitingForAcks, sendQueue->Size());
    for (std::vector<std::shared_ptr<Stream>>::iterator stm = m_incomingStreams.begin(); stm != m_incomingStreams.end(); ++stm)
    {
        if ((*stm)->jitterBuffer)
        {
            int lostCount = (*stm)->jitterBuffer->GetAndResetLostPacketCount();
            if (lostCount > 0 || (lostCount < 0 && m_recvLossCount > static_cast<std::uint32_t>(-lostCount)))
                m_recvLossCount += static_cast<std::uint32_t>(lostCount);
        }
    }
}

void VoIPController::UpdateCongestion()
{
    if (m_conctl && m_encoder)
    {
        std::uint32_t sendLossCount = m_conctl->GetSendLossCount();
        m_sendLossCountHistory.Add(sendLossCount - m_prevSendLossCount);
        m_prevSendLossCount = sendLossCount;
        double packetsPerSec = 1000.0 / m_outgoingStreams[0]->frameDuration;
        double avgSendLossCount = m_sendLossCountHistory.Average() / packetsPerSec;
        //LOGV("avg send loss: %.3f%%", avgSendLossCount*100);

        if (avgSendLossCount > m_packetLossToEnableExtraEC && m_networkType != NetType::GPRS && m_networkType != NetType::EDGE)
        {
            if (!m_shittyInternetMode)
            {
                // Shitty Internet Mode™. Redundant redundancy you can trust.
                m_shittyInternetMode = true;
                for (std::shared_ptr<Stream>& s : m_outgoingStreams)
                {
                    if (s->type == STREAM_TYPE_AUDIO)
                    {
                        s->extraECEnabled = true;
                        SendStreamFlags(*s);
                        break;
                    }
                }
                if (m_encoder)
                    m_encoder->SetSecondaryEncoderEnabled(true);
                LOGW("Enabling extra EC");
                if (m_needRateFlags & NEED_RATE_FLAG_SHITTY_INTERNET_MODE)
                    m_needRate = true;
                m_wasExtraEC = true;
            }
        }

        if (avgSendLossCount > 0.08)
        {
            m_extraEcLevel = 4;
        }
        else if (avgSendLossCount > 0.05)
        {
            m_extraEcLevel = 3;
        }
        else if (avgSendLossCount > 0.02)
        {
            m_extraEcLevel = 2;
        }
        else
        {
            m_extraEcLevel = 0;
        }
        m_encoder->SetPacketLoss(static_cast<int>(avgSendLossCount * 100));
        if (avgSendLossCount > m_rateMaxAcceptableSendLoss)
            m_needRate = true;

        if ((avgSendLossCount < m_packetLossToEnableExtraEC || m_networkType == NetType::EDGE || m_networkType == NetType::GPRS) && m_shittyInternetMode)
        {
            m_shittyInternetMode = false;
            for (std::shared_ptr<Stream>& s : m_outgoingStreams)
            {
                if (s->type == STREAM_TYPE_AUDIO)
                {
                    s->extraECEnabled = false;
                    SendStreamFlags(*s);
                    break;
                }
            }
            if (m_encoder)
                m_encoder->SetSecondaryEncoderEnabled(false);
            LOGW("Disabling extra EC");
        }
        if (!m_wasEncoderLaggy && m_encoder->GetComplexity() < 10)
            m_wasEncoderLaggy = true;
    }
}

void VoIPController::UpdateAudioBitrate()
{
    if (m_encoder && m_conctl)
    {
        double time = GetCurrentTime();
        if ((m_audioInput && !m_audioInput->IsInitialized()) || (m_audioOutput && !m_audioOutput->IsInitialized()))
        {
            LOGE("Audio I/O failed");
            m_lastError = Error::AUDIO_IO;
            SetState(State::FAILED);
        }

        tgvoip::ConctlAct act = m_conctl->GetBandwidthControlAction();
        if (m_shittyInternetMode)
        {
            m_encoder->SetBitrate(8000);
        }
        else if (act == tgvoip::ConctlAct::DECREASE)
        {
            std::uint32_t bitrate = m_encoder->GetBitrate();
            if (bitrate > 8000)
                m_encoder->SetBitrate(bitrate < (m_minAudioBitrate + m_audioBitrateStepDecr) ? m_minAudioBitrate : (bitrate - m_audioBitrateStepDecr));
        }
        else if (act == tgvoip::ConctlAct::INCREASE)
        {
            std::uint32_t bitrate = m_encoder->GetBitrate();
            if (bitrate < m_maxBitrate)
                m_encoder->SetBitrate(bitrate + m_audioBitrateStepIncr);
        }

        if (m_state == State::ESTABLISHED && time - m_lastRecvPacketTime >= m_reconnectingTimeout)
        {
            SetState(State::RECONNECTING);
            if (m_needRateFlags & NEED_RATE_FLAG_RECONNECTING)
                m_needRate = true;
            m_wasReconnecting = true;
            ResetUdpAvailability();
        }

        if (m_state == State::ESTABLISHED || m_state == State::RECONNECTING)
        {
            if (time - m_lastRecvPacketTime >= m_config.recvTimeout)
            {
                const Endpoint& _currentEndpoint = m_endpoints.at(m_currentEndpoint);
                if (_currentEndpoint.type != Endpoint::Type::UDP_RELAY && _currentEndpoint.type != Endpoint::Type::TCP_RELAY)
                {
                    LOGW("Packet receive timeout, switching to relay");
                    m_currentEndpoint = m_preferredRelay;
                    for (std::pair<const std::int64_t, Endpoint>& _e : m_endpoints)
                    {
                        Endpoint& e = _e.second;
                        if (e.type == Endpoint::Type::UDP_P2P_INET || e.type == Endpoint::Type::UDP_P2P_LAN)
                        {
                            e.m_averageRTT = 0;
                            e.m_rtts.Reset();
                        }
                    }
                    if (m_allowP2p)
                    {
                        SendPublicEndpointsRequest();
                    }
                    UpdateDataSavingState();
                    UpdateAudioBitrateLimit();
                    BufferOutputStream s(4);
                    s.WriteInt32(m_dataSavingMode ? INIT_FLAG_DATA_SAVING_ENABLED : 0);
                    if (m_peerVersion < 6)
                    {
                        SendPacketReliably(PktType::NETWORK_CHANGED, s.GetBuffer(), s.GetLength(), 1, 20);
                    }
                    else
                    {
                        Buffer buf(std::move(s));
                        SendExtra(buf, EXTRA_TYPE_NETWORK_CHANGED);
                    }
                    m_lastRecvPacketTime = time;
                }
                else
                {
                    LOGW("Packet receive timeout, disconnecting");
                    m_lastError = Error::TIMEOUT;
                    SetState(State::FAILED);
                }
            }
        }
    }
}

void VoIPController::UpdateSignalBars()
{
    int prevSignalBarCount = GetSignalBarsCount();
    double packetsPerSec = 1000.0 / m_outgoingStreams[0]->frameDuration;
    double avgSendLossCount = m_sendLossCountHistory.Average() / packetsPerSec;

    int signalBarCount = 4;
    if (m_state == State::RECONNECTING || m_waitingForAcks)
        signalBarCount = 1;
    if (m_endpoints.at(m_currentEndpoint).type == Endpoint::Type::TCP_RELAY)
    {
        signalBarCount = std::min(signalBarCount, 3);
    }
    if (avgSendLossCount > 0.1)
    {
        signalBarCount = 1;
    }
    else if (avgSendLossCount > 0.0625)
    {
        signalBarCount = std::min(signalBarCount, 2);
    }
    else if (avgSendLossCount > 0.025)
    {
        signalBarCount = std::min(signalBarCount, 3);
    }

    for (std::shared_ptr<Stream>& stm : m_incomingStreams)
    {
        if (stm->jitterBuffer)
        {
            double avgLateCount[3];
            stm->jitterBuffer->GetAverageLateCount(avgLateCount);
            if (avgLateCount[2] >= 0.2)
                signalBarCount = 1;
            else if (avgLateCount[2] >= 0.1)
                signalBarCount = std::min(signalBarCount, 2);
        }
    }

    m_signalBarsHistory.Add(static_cast<unsigned char>(signalBarCount));
    //LOGV("Signal bar count history %08X", *reinterpret_cast<std::uint32_t *>(&signalBarsHistory));
    int _signalBarCount = GetSignalBarsCount();
    if (_signalBarCount != prevSignalBarCount)
    {
        LOGD("SIGNAL BAR COUNT CHANGED: %d", _signalBarCount);
        if (m_callbacks.signalBarCountChanged)
            m_callbacks.signalBarCountChanged(this, _signalBarCount);
    }
}

void VoIPController::UpdateQueuedPackets()
{
    std::vector<PendingOutgoingPacket> packetsToSend;
    for (std::vector<QueuedPacket>::iterator qp = m_queuedPackets.begin(); qp != m_queuedPackets.end();)
    {
        if (qp->timeout > 0 && qp->firstSentTime > 0 && GetCurrentTime() - qp->firstSentTime >= qp->timeout)
        {
            LOGD("Removing queued packet because of timeout");
            qp = m_queuedPackets.erase(qp);
            continue;
        }
        if (GetCurrentTime() - qp->lastSentTime >= qp->retryInterval)
        {
            m_messageThread.Post(std::bind(&VoIPController::UpdateQueuedPackets, this), qp->retryInterval);
            std::uint32_t seq = GenerateOutSeq();
            qp->seqs.Add(seq);
            qp->lastSentTime = GetCurrentTime();
            //LOGD("Sending queued packet, seq=%u, type=%u, len=%u", seq, qp.type, qp.data.Length());
            Buffer buf(qp->data.Length());
            if (qp->firstSentTime == 0)
                qp->firstSentTime = qp->lastSentTime;
            if (qp->data.Length())
                buf.CopyFrom(qp->data, qp->data.Length());
            packetsToSend.push_back(PendingOutgoingPacket {
                /*.seq=*/seq,
                /*.type=*/qp->type,
                /*.len=*/qp->data.Length(),
                /*.data=*/std::move(buf),
                /*.endpoint=*/0});
        }
        ++qp;
    }
    for (PendingOutgoingPacket& pkt : packetsToSend)
    {
        SendOrEnqueuePacket(std::move(pkt));
    }
}

void VoIPController::SendNopPacket()
{
    if (m_state != State::ESTABLISHED)
        return;
    SendOrEnqueuePacket(PendingOutgoingPacket {
        /*.seq=*/(m_firstSentPing = GenerateOutSeq()),
        /*.type=*/PktType::NOP,
        /*.len=*/0,
        /*.data=*/Buffer(),
        /*.endpoint=*/0});
}

void VoIPController::SendPublicEndpointsRequest()
{
    ENFORCE_MSG_THREAD;
    if (!m_allowP2p)
        return;
    LOGI("Sending public endpoints request");
    for (std::pair<const std::int64_t, Endpoint>& e : m_endpoints)
    {
        if (e.second.type == Endpoint::Type::UDP_RELAY && !e.second.IsIPv6Only())
        {
            SendPublicEndpointsRequest(e.second);
        }
    }
    m_publicEndpointsReqCount++;
    if (m_publicEndpointsReqCount < 10)
    {
        m_messageThread.Post([this] {
            if (m_waitingForRelayPeerInfo)
            {
                LOGW("Resending peer relay info request");
                SendPublicEndpointsRequest();
            }
        },
            5.0);
    }
    else
    {
        m_publicEndpointsReqCount = 0;
    }
}

void VoIPController::TickJitterBufferAndCongestionControl()
{
    // TODO get rid of this and update states of these things internally and retroactively
    for (std::shared_ptr<Stream>& stm : m_incomingStreams)
    {
        if (stm->jitterBuffer)
        {
            stm->jitterBuffer->Tick();
        }
    }
    if (m_conctl)
    {
        m_conctl->Tick();
    }

    //MutexGuard m(queuedPacketsMutex);
    double currentTime = GetCurrentTime();
    double rtt = GetAverageRTT();
    double packetLossTimeout = std::max(rtt * 2.0, 0.1);
    for (RecentOutgoingPacket& pkt : m_recentOutgoingPackets)
    {
        if (pkt.ackTime != 0.0 || pkt.lost)
            continue;
        if (currentTime - pkt.sendTime > packetLossTimeout)
        {
            pkt.lost = true;
            m_sendLosses++;
            LOGW("Outgoing packet lost: seq=%u, type=%s, size=%u", pkt.seq, GetPacketTypeString(pkt.type).c_str(), static_cast<unsigned int>(pkt.size));
            if (pkt.sender)
            {
                pkt.sender->PacketLost(pkt.seq, pkt.type, pkt.size);
            }
            else if (pkt.type == PktType::STREAM_DATA)
            {
                m_conctl->PacketLost(pkt.seq);
            }
        }
    }
}

#pragma mark - Endpoint

Endpoint::Endpoint(std::int64_t id, std::uint16_t port, const IPv4Address& _address, const IPv6Address& _v6address, Type type, const std::uint8_t peerTag[16])
    : address(NetworkAddress::IPv4(_address.addr))
    , v6address(NetworkAddress::IPv6(_v6address.addr))
{
    this->id = id;
    this->port = port;
    this->type = type;
    std::memcpy(this->peerTag, peerTag, 16);
    if (type == Type::UDP_RELAY && ServerConfig::GetSharedInstance()->GetBoolean("force_tcp", false))
        this->type = Type::TCP_RELAY;

    m_lastPingSeq = 0;
    m_lastPingTime = 0;
    m_averageRTT = 0;
    m_socket = nullptr;
    m_udpPongCount = 0;
}

Endpoint::Endpoint(std::int64_t id, std::uint16_t port, const NetworkAddress _address, const NetworkAddress _v6address, Type type, const std::uint8_t peerTag[16])
    : address(_address)
    , v6address(_v6address)
{
    this->id = id;
    this->port = port;
    this->type = type;
    std::memcpy(this->peerTag, peerTag, 16);
    if (type == Type::UDP_RELAY && ServerConfig::GetSharedInstance()->GetBoolean("force_tcp", false))
        this->type = Type::TCP_RELAY;

    m_lastPingSeq = 0;
    m_lastPingTime = 0;
    m_averageRTT = 0;
    m_socket = nullptr;
    m_udpPongCount = 0;
}

Endpoint::Endpoint()
    : address(NetworkAddress::Empty())
    , v6address(NetworkAddress::Empty())
{
    m_lastPingSeq = 0;
    m_lastPingTime = 0;
    m_averageRTT = 0;
    m_socket = nullptr;
    m_udpPongCount = 0;
}

const NetworkAddress& Endpoint::GetAddress() const
{
    return IsIPv6Only() ? v6address : address;
}

NetworkAddress& Endpoint::GetAddress()
{
    return IsIPv6Only() ? v6address : address;
}

bool Endpoint::IsIPv6Only() const
{
    return address.IsEmpty() && !v6address.IsEmpty();
}

std::int64_t Endpoint::CleanID() const
{
    std::int64_t _id = id;
    if (type == Type::TCP_RELAY)
    {
        _id = _id ^ (static_cast<std::int64_t>(FOURCC('T', 'C', 'P', ' ')) << 32);
    }
    if (IsIPv6Only())
    {
        _id = _id ^ (static_cast<std::int64_t>(FOURCC('I', 'P', 'v', '6')) << 32);
    }
    return _id;
}

Endpoint::~Endpoint()
{
    if (m_socket)
    {
        m_socket->Close();
    }
}

#pragma mark - AudioInputTester

AudioInputTester::AudioInputTester(std::string deviceID)
    : m_deviceID(std::move(deviceID))
{
    m_io = audio::AudioIO::Create(deviceID, "default");
    if (m_io->Failed())
    {
        LOGE("Audio IO failed");
        return;
    }
    m_input = m_io->GetInput();
    m_input->SetCallback([](std::uint8_t* data, std::size_t size, void* ctx) -> std::size_t
        {
            reinterpret_cast<AudioInputTester*>(ctx)->Update(reinterpret_cast<std::int16_t*>(data), size / 2);
            return 0;
        },
        this);
    m_input->Start();
}

AudioInputTester::~AudioInputTester()
{
    m_input->Stop();
    delete m_io;
}

void AudioInputTester::Update(std::int16_t* samples, std::size_t count)
{
    for (std::size_t i = 0; i < count; i++)
    {
        std::int16_t s = static_cast<std::int16_t>(std::abs(samples[i]));
        if (s > m_maxSample)
            m_maxSample = s;
    }
}

float AudioInputTester::GetAndResetLevel()
{
    float s = m_maxSample;
    m_maxSample = 0;
    return s / std::numeric_limits<std::int16_t>::max();
}

bool AudioInputTester::Failed() const
{
    return (m_io != nullptr) && m_io->Failed();
}
