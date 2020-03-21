//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#ifndef __VOIPCONTROLLER_H
#define __VOIPCONTROLLER_H

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#ifdef __APPLE__
#include "os/darwin/AudioUnitIO.h"
#include <TargetConditionals.h>
#endif
#include "BlockingQueue.h"
#include "Buffers.h"
#include "CongestionControl.h"
#include "EchoCanceller.h"
#include "JitterBuffer.h"
#include "MessageThread.h"
#include "NetworkSocket.h"
#include "OpusDecoder.h"
#include "OpusEncoder.h"
#include "PacketReassembler.h"
#include "audio/AudioIO.h"
#include "audio/AudioInput.h"
#include "audio/AudioOutput.h"
#include "utils.h"
#include "video/ScreamCongestionController.h"
#include "video/VideoRenderer.h"
#include "video/VideoSource.h"
#include <atomic>
#include <map>
#include <memory>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#define LIBTGVOIP_VERSION "2.6"

#ifdef _WIN32
#undef GetCurrentTime
#undef Error::TIMEOUT
#endif

#define TGVOIP_PEER_CAP_GROUP_CALLS 1
#define TGVOIP_PEER_CAP_VIDEO_CAPTURE 2
#define TGVOIP_PEER_CAP_VIDEO_DISPLAY 4

namespace tgvoip
{

enum class Proxy
{
    NONE = 0,
    SOCKS5,
    //HTTP,
};

enum class State
{
    WAIT_INIT = 1,
    WAIT_INIT_ACK,
    ESTABLISHED,
    FAILED,
    RECONNECTING,
};

enum class Error
{
    UNKNOWN = 0,
    INCOMPATIBLE,
    TIMEOUT,
    AUDIO_IO,
    PROXY,
};

enum class PktType : std::uint8_t
{
    INIT = 1,
    INIT_ACK,
    STREAM_STATE,
    STREAM_DATA,
    UPDATE_STREAMS,
    PING,
    PONG,
    STREAM_DATA_X2,
    STREAM_DATA_X3,
    LAN_ENDPOINT,
    NETWORK_CHANGED,
    SWITCH_PREF_RELAY,
    SWITCH_TO_P2P,
    NOP,
//    GROUP_CALL_KEY,		// replaced with 'extra' in 2.1 (protocol v6)
//    REQUEST_GROUP,
    STREAM_EC,
};

enum class ExtraType : std::uint8_t
{
    STREAM_FLAGS = 1,
    STREAM_CSD,
    LAN_ENDPOINT,
    NETWORK_CHANGED,
    GROUP_CALL_KEY,
    REQUEST_GROUP,
    IPV6_ENDPOINT,
};

enum class StreamType : std::uint8_t
{
    AUDIO = 1,
    VIDEO,
};

enum class NetType
{
    UNKNOWN = 0,
    GPRS,
    EDGE,
    THREE_G,
    HSPA,
    LTE,
    WIFI,
    ETHERNET,
    OTHER_HIGH_SPEED,
    OTHER_LOW_SPEED,
    DIALUP,
    OTHER_MOBILE,
};

enum class DataSaving
{
    NEVER = 0,
    MOBILE,
    ALWAYS,
};

struct CryptoFunctions
{
    void (*rand_bytes)(std::uint8_t* buffer, std::size_t length);
    void (*sha1)(std::uint8_t* msg, std::size_t length, std::uint8_t* output);
    void (*sha256)(std::uint8_t* msg, std::size_t length, std::uint8_t* output);
    void (*aes_ige_encrypt)(std::uint8_t* in, std::uint8_t* out, std::size_t length, std::uint8_t* key, std::uint8_t* iv);
    void (*aes_ige_decrypt)(std::uint8_t* in, std::uint8_t* out, std::size_t length, std::uint8_t* key, std::uint8_t* iv);
    void (*aes_ctr_encrypt)(std::uint8_t* inout, std::size_t length, std::uint8_t* key, std::uint8_t* iv, std::uint8_t* ecount, std::uint32_t* num);
    void (*aes_cbc_encrypt)(std::uint8_t* in, std::uint8_t* out, std::size_t length, std::uint8_t* key, std::uint8_t* iv);
    void (*aes_cbc_decrypt)(std::uint8_t* in, std::uint8_t* out, std::size_t length, std::uint8_t* key, std::uint8_t* iv);
};

struct CellularCarrierInfo
{
    std::string name;
    std::string mcc;
    std::string mnc;
    std::string countryCode;
};

// API compatibility
struct IPv4Address
{
    IPv4Address(std::string addr);
    std::string addr;
};
struct IPv6Address
{
    IPv6Address(std::string addr);
    std::string addr;
};

class Endpoint
{
    friend class VoIPController;
    friend class VoIPGroupController;

public:
    enum class Type
    {
        UDP_P2P_INET = 1,
        UDP_P2P_LAN,
        UDP_RELAY,
        TCP_RELAY,
    };

    Endpoint(std::int64_t id, std::uint16_t port, const IPv4Address& address, const IPv6Address& v6address, Type type, const std::uint8_t peerTag[16]);
    Endpoint(std::int64_t id, std::uint16_t port, const NetworkAddress address, const NetworkAddress v6address, Type type, const std::uint8_t peerTag[16]);
    Endpoint();
    ~Endpoint();
    const NetworkAddress& GetAddress() const;
    NetworkAddress& GetAddress();
    bool IsIPv6Only() const;
    std::int64_t CleanID() const;
    std::int64_t id;
    std::uint16_t port;
    NetworkAddress address;
    NetworkAddress v6address;
    Type type;
    std::uint8_t peerTag[16];

private:
    double m_lastPingTime;
    std::uint32_t m_lastPingSeq;
    HistoricBuffer<double, 6> m_rtts;
    HistoricBuffer<double, 4> m_selfRtts;
    std::map<std::int64_t, double> m_udpPingTimes;
    double m_averageRTT;
    std::shared_ptr<NetworkSocket> m_socket;
    int m_udpPongCount;
    int m_totalUdpPings = 0;
    int m_totalUdpPingReplies = 0;
};

struct AudioDevice
{
    std::string id;
    std::string displayName;
};

class AudioOutputDevice : public AudioDevice
{
};

class AudioInputDevice : public AudioDevice
{
};

class AudioInputTester
{
public:
    AudioInputTester(const std::string m_deviceID);
    ~AudioInputTester();
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(AudioInputTester);
    float GetAndResetLevel();
    bool Failed() const;

private:
    void Update(std::int16_t* samples, std::size_t count);
    audio::AudioIO* m_io = nullptr;
    audio::AudioInput* m_input = nullptr;
    std::int16_t m_maxSample = 0;
    std::string m_deviceID;
};

class PacketSender;

namespace video
{

class VideoPacketSender;

} // namespace video

class VoIPController
{
    friend class VoIPGroupController;
    friend class PacketSender;

public:
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(VoIPController);
    struct Config
    {
        Config(double initTimeout = 30.0, double recvTimeout = 20.0, DataSaving dataSaving = DataSaving::NEVER,
               bool enableAEC = false, bool enableNS = false, bool enableAGC = false, bool enableCallUpgrade = false);

        double initTimeout;
        double recvTimeout;
        DataSaving dataSaving;
#ifndef _WIN32
        std::string logFilePath = "";
        std::string statsDumpFilePath = "";
#else
        std::wstring logFilePath = L"";
        std::wstring statsDumpFilePath = L"";
#endif

        bool enableAEC;
        bool enableNS;
        bool enableAGC;

        bool enableCallUpgrade;

        bool logPacketStats = false;
        bool enableVolumeControl = false;

        bool enableVideoSend = false;
        bool enableVideoReceive = false;
    };

    struct TrafficStats
    {
        std::uint64_t bytesSentWifi;
        std::uint64_t bytesRecvdWifi;
        std::uint64_t bytesSentMobile;
        std::uint64_t bytesRecvdMobile;
    };

    struct PendingOutgoingPacket
    {
        PendingOutgoingPacket(std::uint32_t seq, PktType type, std::size_t len, Buffer&& data, std::int64_t endpoint);
        PendingOutgoingPacket(PendingOutgoingPacket&& other);
        PendingOutgoingPacket& operator=(PendingOutgoingPacket&& other);
        TGVOIP_DISALLOW_COPY_AND_ASSIGN(PendingOutgoingPacket);

        std::uint32_t seq;
        PktType type;
        std::size_t len;
        Buffer data;
        std::int64_t endpoint;
    };

    struct Stream
    {
        std::int32_t userID;
        std::uint8_t id;
        StreamType type;
        std::uint32_t codec;
        bool enabled;
        bool extraECEnabled;
        std::uint16_t frameDuration;
        std::shared_ptr<JitterBuffer> jitterBuffer;
        std::shared_ptr<OpusDecoder> decoder;
        std::shared_ptr<PacketReassembler> packetReassembler;
        std::shared_ptr<CallbackWrapper> callbackWrapper;
        std::vector<Buffer> codecSpecificData;
        bool csdIsValid = false;
        bool paused = false;
        int resolution;
        unsigned int width = 0;
        unsigned int height = 0;
        std::uint16_t rotation = 0;
    };

    struct ProtocolInfo
    {
        std::uint32_t version;
        std::uint32_t maxVideoResolution;
        std::vector<std::uint32_t> videoDecoders;
        bool videoCaptureSupported;
        bool videoDisplaySupported;
        bool callUpgradeSupported;
    };

    VoIPController();
    virtual ~VoIPController();

    /**
     * Set the initial endpoints (relays)
     * @param endpoints Endpoints converted from phone.PhoneConnection TL objects
     * @param allowP2p Whether p2p connectivity is allowed
     * @param connectionMaxLayer The max_layer field from the phoneCallProtocol object returned by Telegram server.
     * DO NOT HARDCODE THIS VALUE, it's extremely important for backwards compatibility.
     */
    void SetRemoteEndpoints(std::vector<Endpoint> m_endpoints, bool m_allowP2p, std::int32_t m_connectionMaxLayer);

    /**
     * Initialize and start all the internal threads
     */
    void Start();

    /**
     * Stop any internal threads. Don't call any other methods after this.
     */
    void Stop();

    /**
     * Initiate connection
     */
    void Connect();
    Endpoint& GetRemoteEndpoint();

    /**
     * Get the debug info string to be displayed in client UI
     */
    virtual std::string GetDebugString();

    /**
     * Notify the library of network type change
     * @param type The new network type
     */
    virtual void SetNetworkType(NetType type);

    /**
     * Get the average round-trip time for network packets
     * @return
     */
    double GetAverageRTT();
    static double GetCurrentTime();

    /**
     * Use this field to store any of your context data associated with this call
     */
    void* implData;

    virtual void SetMicMute(bool mute);

    void SetEncryptionKey(char* key, bool m_isOutgoing);

    void SetConfig(const Config& cfg);
    void DebugCtl(int request, int param);
    void GetStats(TrafficStats* m_stats);

    std::int64_t GetPreferredRelayID();
    Error GetLastError();

    static CryptoFunctions crypto;
    static const char* GetVersion();
    std::string GetDebugLog();

    static std::vector<AudioInputDevice> EnumerateAudioInputs();
    static std::vector<AudioOutputDevice> EnumerateAudioOutputs();

    void SetCurrentAudioInput(std::string id);
    void SetCurrentAudioOutput(std::string id);

    std::string GetCurrentAudioInputID();
    std::string GetCurrentAudioOutputID();

    /**
     * Set the proxy server to route the data through. Call this before connecting.
     * @param protocol Proxy::NONE or Proxy::SOCKS5
     * @param address IP address or domain name of the server
     * @param port Port of the server
     * @param username Username; empty string for anonymous
     * @param password Password; empty string if none
     */
    void SetProxy(Proxy protocol, std::string address, std::uint16_t port, std::string username, std::string password);

    /**
     * Get the number of signal bars to display in the client UI.
     * @return the number of signal bars, from 1 to 4
     */
    int GetSignalBarsCount();

    /**
     * Enable or disable AGC (automatic gain control) on audio output. Should only be enabled on phones when the earpiece speaker is being used.
     * The audio output will be louder with this on.
     * AGC with speakerphone or other kinds of loud speakers has detrimental effects on some echo cancellation implementations.
     * @param enabled I usually pick argument names to be self-explanatory
     */
    void SetAudioOutputGainControlEnabled(bool enabled);

    /**
     * Get the additional capabilities of the peer client app
     * @return corresponding TGVOIP_PEER_CAP_* flags OR'ed together
     */
    std::uint32_t GetPeerCapabilities();

    /**
     * Send the peer the key for the group call to prepare this private call to an upgrade to a E2E group call.
     * The peer must have the TGVOIP_PEER_CAP_GROUP_CALLS capability. After the peer acknowledges the key, Callbacks::groupCallKeySent will be called.
     * @param key newly-generated group call key, must be exactly 265 bytes long
     */
    void SendGroupCallKey(std::uint8_t* key);

    /**
     * In an incoming call, request the peer to generate a new encryption key, send it to you and upgrade this call to a E2E group call.
     */
    void RequestCallUpgrade();

    void SetEchoCancellationStrength(int strength);
    State GetConnectionState() const;
    bool NeedRate();

    /**
     * Get the maximum connection layer supported by this libtgvoip version.
     * Pass this as <code>max_layer</code> in the phone.phoneConnection TL object when requesting and accepting calls.
     */
    static std::int32_t GetConnectionMaxLayer()
    {
        return 92;
    }

    /**
     * Get the persistable state of the library, like proxy capabilities, to save somewhere on the disk. Call this at the end of the call.
     * Using this will speed up the connection establishment in some cases.
     */
    std::vector<std::uint8_t> GetPersistentState();

    /**
     * Load the persistable state. Call this before starting the call.
     */
    void SetPersistentState(const std::vector<std::uint8_t>& m_state);

#if defined(TGVOIP_USE_CALLBACK_AUDIO_IO)
    void SetAudioDataCallbacks(std::function<void(std::int16_t*, std::size_t)> input, std::function<void(std::int16_t*, std::size_t)> output, std::function<void(std::int16_t*, std::size_t)> preprocessed);
#endif

    void SetVideoCodecSpecificData(const std::vector<Buffer>& data);

    struct Callbacks
    {
        void (*connectionStateChanged)(VoIPController*, State);
        void (*signalBarCountChanged)(VoIPController*, int);
        void (*groupCallKeySent)(VoIPController*);
        void (*groupCallKeyReceived)(VoIPController*, const std::uint8_t*);
        void (*upgradeToGroupCallRequested)(VoIPController*);
    };
    void SetCallbacks(Callbacks m_callbacks);

    float GetOutputLevel() const;

    void SetVideoSource(video::VideoSource* source);
    void SetVideoRenderer(video::VideoRenderer* renderer);

    void SetInputVolume(float level);
    void SetOutputVolume(float level);
#if defined(__APPLE__) && defined(TARGET_OS_OSX)
    void SetAudioOutputDuckingEnabled(bool enabled);
#endif

#ifdef __APPLE__
    static double machTimebase;
    static std::uint64_t machTimestart;
#endif
#ifdef _WIN32
    static std::int64_t win32TimeScale;
    static bool didInitWin32TimeScale;
#endif

protected:
    struct RecentOutgoingPacket
    {
        std::uint32_t seq;
        std::uint16_t id; // for group calls only
        double sendTime;
        double ackTime;
        PktType type;
        std::uint32_t size;
        PacketSender* sender;
        bool lost;
    };

    struct QueuedPacket
    {
        Buffer data;
        PktType type;
        HistoricBuffer<std::uint32_t, 16> seqs;
        double firstSentTime;
        double lastSentTime;
        double retryInterval;
        double timeout;
    };

    virtual void ProcessIncomingPacket(NetworkPacket& packet, Endpoint& srcEndpoint);
    virtual void ProcessExtraData(Buffer& data);
    virtual void WritePacketHeader(std::uint32_t m_seq, BufferOutputStream* s, PktType type, std::uint32_t length, PacketSender* source);
    virtual void SendPacket(std::uint8_t* data, std::size_t len, Endpoint& ep, PendingOutgoingPacket& srcPacket);
    virtual void SendInit();
    virtual void SendUdpPing(Endpoint& endpoint);
    virtual void SendRelayPings();
    virtual void OnAudioOutputReady();
    virtual void SendExtra(Buffer& data, ExtraType type);
    void SendStreamFlags(Stream& stream);
    void InitializeTimers();
    void ResetEndpointPingStats();
    void SendVideoFrame(const Buffer& frame, std::uint32_t flags, std::uint32_t rotation);
    void ProcessIncomingVideoFrame(Buffer frame, std::uint32_t pts, bool keyframe, std::uint16_t rotation);
    std::shared_ptr<Stream> GetStreamByType(StreamType, bool outgoing);
    std::shared_ptr<Stream> GetStreamByID(std::uint8_t id, bool outgoing);
    Endpoint* GetEndpointForPacket(const PendingOutgoingPacket& pkt);
    bool SendOrEnqueuePacket(PendingOutgoingPacket pkt, bool enqueue = true, PacketSender* source = nullptr);
    static std::string NetworkTypeToString(NetType type);
    CellularCarrierInfo GetCarrierInfo();

private:
    struct UnacknowledgedExtraData;

    struct UnacknowledgedExtraData
    {
        ExtraType type;
        Buffer data;
        std::uint32_t firstContainingSeq;
    };

    struct RecentIncomingPacket
    {
        std::uint32_t seq;
        double recvTime;
    };

    struct DebugLoggedPacket
    {
        std::int32_t seq;
        double timestamp;
        std::int32_t length;
    };

    struct RawPendingOutgoingPacket
    {
        TGVOIP_MOVE_ONLY(RawPendingOutgoingPacket);
        NetworkPacket packet;
        std::shared_ptr<NetworkSocket> socket;
    };

    enum class UdpState
    {
        UNKNOWN = 0,
        PING_PENDING,
        PING_SENT,
        AVAILABLE,
        NOT_AVAILABLE,
        BAD,
    };

    void RunRecvThread();
    void RunSendThread();
    void HandleAudioInput(std::uint8_t* data, std::size_t len, std::uint8_t* secondaryData, std::size_t secondaryLen);
    void UpdateAudioBitrateLimit();
    void SetState(State m_state);
    void UpdateAudioOutputState();
    void InitUDPProxy();
    void UpdateDataSavingState();
    void KDF(std::uint8_t* msgKey, std::size_t x, std::uint8_t* aesKey, std::uint8_t* aesIv);
    void KDF2(std::uint8_t* msgKey, std::size_t x, std::uint8_t* aesKey, std::uint8_t* aesIv);
    void SendPublicEndpointsRequest();
    void SendPublicEndpointsRequest(const Endpoint& relay);
    Endpoint& GetEndpointByType(Endpoint::Type type);
    void SendPacketReliably(PktType type, std::uint8_t* data, std::size_t len, double retryInterval, double timeout);
    std::uint32_t GenerateOutSeq();
    void ActuallySendPacket(NetworkPacket pkt, Endpoint& ep);
    void InitializeAudio();
    void StartAudio();
    void ProcessAcknowledgedOutgoingExtra(UnacknowledgedExtraData& extra);
    void AddIPv6Relays();
    void AddTCPRelays();
    void SendUdpPings();
    void EvaluateUdpPingResults();
    void UpdateRTT();
    void UpdateCongestion();
    void UpdateAudioBitrate();
    void UpdateSignalBars();
    void UpdateQueuedPackets();
    void SendNopPacket();
    void TickJitterBufferAndCongestionControl();
    void ResetUdpAvailability();
    std::string GetPacketTypeString(PktType type);
    void SetupOutgoingVideoStream();
    bool WasOutgoingPacketAcknowledged(std::uint32_t m_seq);
    RecentOutgoingPacket* GetRecentOutgoingPacket(std::uint32_t m_seq);
    void NetworkPacketReceived(std::shared_ptr<NetworkPacket> packet);
    void TrySendQueuedPackets();

    State m_state;
    NetType m_networkType;

    std::map<std::int64_t, Endpoint> m_endpoints;
    std::int64_t m_currentEndpoint = 0;
    // Locked whenever the endpoints vector is modified (but not endpoints themselves) and whenever iterated outside of messageThread.
    // After the call is started, only messageThread is allowed to modify the endpoints vector.
    Mutex m_endpointsMutex;

    std::int64_t m_preferredRelay = 0;
    std::int64_t m_peerPreferredRelay = 0;

    std::atomic<bool> m_runReceiver;

    std::atomic<std::uint32_t> m_seq;
    std::uint32_t m_lastRemoteSeq;
    std::uint32_t m_lastRemoteAckSeq;
    std::uint32_t m_lastSentSeq;

    std::vector<RecentOutgoingPacket> m_recentOutgoingPackets;
    std::vector<std::uint32_t> m_recentIncomingPackets;

    HistoricBuffer<std::uint32_t, 10, double> m_sendLossCountHistory;

    std::uint32_t m_audioTimestampIn;
    std::uint32_t m_audioTimestampOut;

    tgvoip::audio::AudioIO* m_audioIO = nullptr;
    tgvoip::audio::AudioInput* m_audioInput = nullptr;
    tgvoip::audio::AudioOutput* m_audioOutput = nullptr;

    OpusEncoder* m_encoder;

    std::vector<PendingOutgoingPacket> m_sendQueue;

    EchoCanceller* m_echoCanceller;
    int m_echoCancellationStrength;

    std::atomic<bool> m_stopping;
    bool m_audioOutStarted;

    Thread* m_recvThread;
    Thread* m_sendThread;

    std::uint32_t m_packetsReceived;
    std::uint32_t m_recvLossCount;
    std::uint32_t m_prevSendLossCount;
    std::uint32_t m_firstSentPing;

    HistoricBuffer<double, 32> m_rttHistory;

    bool m_waitingForAcks;

    int m_dontSendPackets;
    Error m_lastError;
    bool m_micMuted;
    std::uint32_t m_maxBitrate;

    std::vector<std::shared_ptr<Stream>> m_outgoingStreams;
    std::vector<std::shared_ptr<Stream>> m_incomingStreams;

    std::uint8_t m_encryptionKey[256];
    std::uint8_t m_keyFingerprint[8];
    std::uint8_t m_callID[16];

    double m_stateChangeTime;
    bool m_waitingForRelayPeerInfo;
    bool m_allowP2p;
    bool m_dataSavingMode;
    bool m_dataSavingRequestedByPeer;
    std::string m_activeNetItfName;
    double m_publicEndpointsReqTime;
    std::vector<QueuedPacket> m_queuedPackets;
    double m_connectionInitTime;
    double m_lastRecvPacketTime;
    std::int32_t m_peerVersion;
    CongestionControl* m_conctl;

    bool m_receivedInit;
    bool m_receivedInitAck;
    bool m_isOutgoing;

    NetworkSocket* m_udpSocket;
    NetworkSocket* m_realUdpSocket;

    Config m_config;
    TrafficStats m_stats;
    FILE* m_statsDump;

    std::string m_currentAudioInput;
    std::string m_currentAudioOutput;

    bool m_useTCP;
    bool m_useUDP;
    bool m_didAddTcpRelays;

    SocketSelectCanceller* m_selectCanceller;
    HistoricBuffer<std::uint8_t, 4, int> m_signalBarsHistory;
    bool m_audioStarted = false;

    UdpState m_udpConnectivityState;
    double m_lastUdpPingTime;
    int m_udpPingCount;

    Proxy m_proxyProtocol;
    std::string m_proxyAddress;
    std::uint16_t m_proxyPort;
    std::string m_proxyUsername;
    std::string m_proxyPassword;
    NetworkAddress m_resolvedProxyAddress = NetworkAddress::Empty();

    std::uint32_t m_peerCapabilities;
    Callbacks m_callbacks;
    bool m_didReceiveGroupCallKey;
    bool m_didReceiveGroupCallKeyAck;
    bool m_didSendGroupCallKey;
    bool m_didSendUpgradeRequest;
    bool m_didInvokeUpgradeCallback;

    std::int32_t m_connectionMaxLayer;
    bool m_useMTProto2;
    bool m_setCurrentEndpointToTCP;

    std::vector<UnacknowledgedExtraData> m_currentExtras;
    std::unordered_map<ExtraType, std::uint64_t> m_lastReceivedExtrasByType;

    bool m_useIPv6;
    bool m_peerIPv6Available;
    bool m_didAddIPv6Relays;
    bool m_didSendIPv6Endpoint;
    NetworkAddress m_myIPv6 = NetworkAddress::Empty();

    bool m_shittyInternetMode;
    int m_extraEcLevel = 0;
    std::vector<Buffer> m_ecAudioPackets;

    int m_publicEndpointsReqCount = 0;
    bool m_wasEstablished = false;
    bool m_receivedFirstStreamPacket = false;
    std::atomic<std::uint32_t> m_unsentStreamPackets;
    HistoricBuffer<std::uint32_t, 5> m_unsentStreamPacketsHistory;
    bool m_needReInitUdpProxy = true;
    bool m_needRate = false;
    std::vector<DebugLoggedPacket> m_debugLoggedPackets;
    BufferPool<1024, 32> m_outgoingAudioBufferPool;
    BlockingQueue<RawPendingOutgoingPacket> m_rawSendQueue;

    std::uint32_t m_initTimeoutID = MessageThread::INVALID_ID;
    std::uint32_t m_udpPingTimeoutID = MessageThread::INVALID_ID;

    effects::Volume m_outputVolume;
    effects::Volume m_inputVolume;

    std::vector<std::uint32_t> m_peerVideoDecoders;

    MessageThread m_messageThread;


    // Locked while audio i/o is being initialized and deinitialized so as to allow it to fully initialize before deinitialization begins.
    Mutex m_audioIOMutex;

#if defined(TGVOIP_USE_CALLBACK_AUDIO_IO)
    std::function<void(std::int16_t*, std::size_t)> m_audioInputDataCallback;
    std::function<void(std::int16_t*, std::size_t)> m_audioOutputDataCallback;
    std::function<void(std::int16_t*, std::size_t)> m_audioPreprocDataCallback;
    ::OpusDecoder* m_preprocDecoder = nullptr;
    std::int16_t m_preprocBuffer[4096];
#endif
#if defined(__APPLE__) && defined(TARGET_OS_OSX)
    bool macAudioDuckingEnabled = true;
#endif

    video::VideoSource* m_videoSource = nullptr;
    video::VideoRenderer* m_videoRenderer = nullptr;
    std::uint32_t m_lastReceivedVideoFrameNumber = std::numeric_limits<std::uint32_t>::max();

    video::VideoPacketSender* m_videoPacketSender = nullptr;
    std::uint32_t m_sendLosses = 0;
    std::uint32_t m_unacknowledgedIncomingPacketCount = 0;

    ProtocolInfo m_protocolInfo =
    {
        .version = 0,
        .maxVideoResolution = 0,
        .videoDecoders = {},
        .videoCaptureSupported = false,
        .videoDisplaySupported = false,
        .callUpgradeSupported = false
    };

    /*** debug report problems ***/
    bool m_wasReconnecting = false;
    bool m_wasExtraEC = false;
    bool m_wasEncoderLaggy = false;
    bool m_wasNetworkHandover = false;

    /*** persistable state values ***/
    bool m_proxySupportsUDP = true;
    bool m_proxySupportsTCP = true;
    std::string m_lastTestedProxyServer = "";

    /*** server config values ***/
    std::uint32_t m_maxAudioBitrate;
    std::uint32_t m_maxAudioBitrateEDGE;
    std::uint32_t m_maxAudioBitrateGPRS;
    std::uint32_t m_maxAudioBitrateSaving;
    std::uint32_t m_initAudioBitrate;
    std::uint32_t m_initAudioBitrateEDGE;
    std::uint32_t m_initAudioBitrateGPRS;
    std::uint32_t m_initAudioBitrateSaving;
    std::uint32_t m_minAudioBitrate;
    std::uint32_t m_audioBitrateStepIncr;
    std::uint32_t m_audioBitrateStepDecr;
    double m_relaySwitchThreshold;
    double m_p2pToRelaySwitchThreshold;
    double m_relayToP2pSwitchThreshold;
    double m_reconnectingTimeout;
    std::uint32_t m_needRateFlags;
    double m_rateMaxAcceptableRTT;
    double m_rateMaxAcceptableSendLoss;
    double m_packetLossToEnableExtraEC;
    std::uint32_t m_maxUnsentStreamPackets;
    std::uint32_t m_unackNopThreshold;
};

class VoIPGroupController : public VoIPController
{
public:
    VoIPGroupController(std::int32_t m_timeDifference);
    ~VoIPGroupController() override;
    void SetGroupCallInfo(std::uint8_t* m_encryptionKey, std::uint8_t* reflectorGroupTag, std::uint8_t* m_reflectorSelfTag,
                          std::uint8_t* m_reflectorSelfSecret, std::uint8_t* m_reflectorSelfTagHash, std::int32_t selfUserID,
                          NetworkAddress reflectorAddress, NetworkAddress reflectorAddressV6, std::uint16_t reflectorPort);
    void AddGroupCallParticipant(std::int32_t userID, std::uint8_t* memberTagHash, std::uint8_t* serializedStreams, std::size_t streamsLength);
    void RemoveGroupCallParticipant(std::int32_t userID);
    float GetParticipantAudioLevel(std::int32_t userID);
    void SetMicMute(bool mute) override;
    void SetParticipantVolume(std::int32_t userID, float volume);
    void SetParticipantStreams(std::int32_t userID, std::uint8_t* serializedStreams, std::size_t length);
    static std::size_t GetInitialStreams(std::uint8_t* buf, std::size_t size);

    struct Callbacks : public VoIPController::Callbacks
    {
        void (*updateStreams)(VoIPGroupController*, std::uint8_t*, std::size_t);
        void (*participantAudioStateChanged)(VoIPGroupController*, std::int32_t, bool);
    };
    void SetCallbacks(Callbacks m_callbacks);
    std::string GetDebugString() override;
    void SetNetworkType(NetType type) override;

protected:
    void ProcessIncomingPacket(NetworkPacket& packet, Endpoint& srcEndpoint) override;
    void SendInit() override;
    void SendUdpPing(Endpoint& endpoint) override;
    void SendRelayPings() override;
    void SendPacket(std::uint8_t* data, std::size_t len, Endpoint& ep, PendingOutgoingPacket& srcPacket) override;
    void WritePacketHeader(std::uint32_t m_seq, BufferOutputStream* s, PktType type,
                           std::uint32_t length, PacketSender* sender = nullptr) override;
    void OnAudioOutputReady() override;

private:
    struct GroupCallParticipant
    {
        std::int32_t userID;
        std::uint8_t memberTagHash[32];
        std::vector<std::shared_ptr<Stream>> streams;
        AudioLevelMeter* levelMeter;
    };

    struct PacketIdMapping
    {
        std::uint32_t seq;
        std::uint16_t id;
        double ackTime;
    };

    std::int32_t GetCurrentUnixtime();
    std::vector<std::shared_ptr<Stream>> DeserializeStreams(BufferInputStream& in);
    void SendRecentPacketsRequest();
    void SendSpecialReflectorRequest(std::uint8_t* data, std::size_t len);
    void SerializeAndUpdateOutgoingStreams();

    std::vector<GroupCallParticipant> m_participants;
    std::uint8_t m_reflectorSelfTag[16];
    std::uint8_t m_reflectorSelfSecret[16];
    std::uint8_t m_reflectorSelfTagHash[32];
    std::int32_t m_userSelfID;
    Endpoint m_groupReflector;
    AudioMixer* m_audioMixer;
    AudioLevelMeter m_selfLevelMeter;
    Callbacks m_groupCallbacks;
    std::vector<PacketIdMapping> m_recentSentPackets;
    Mutex m_sentPacketsMutex;
    Mutex m_participantsMutex;
    std::int32_t m_timeDifference;
};

} // namespace tgvoip

#endif // __VOIPCONTROLLER_H
