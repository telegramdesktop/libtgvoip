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
    //PROXY_HTTP
};

enum class State
{
    WAIT_INIT = 1,
    WAIT_INIT_ACK,
    ESTABLISHED,
    FAILED,
    RECONNECTING
};

enum class Error
{
    UNKNOWN = 0,
    INCOMPATIBLE,
    TIMEOUT,
    AUDIO_IO,
    PROXY
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
    OTHER_MOBILE
};

enum class DataSaving
{
    NEVER = 0,
    MOBILE,
    ALWAYS
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
    IPv4Address(std::string addr)
        : addr(addr) {}
    std::string addr;
};
struct IPv6Address
{
    IPv6Address(std::string addr)
        : addr(addr) {}
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
        TCP_RELAY
    };

    Endpoint(std::int64_t id, std::uint16_t port, const IPv4Address& address, const IPv6Address& v6address, Type type, const unsigned char peerTag[16]);
    Endpoint(std::int64_t id, std::uint16_t port, const NetworkAddress address, const NetworkAddress v6address, Type type, const unsigned char peerTag[16]);
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
    unsigned char peerTag[16];

private:
    double lastPingTime;
    std::uint32_t lastPingSeq;
    HistoricBuffer<double, 6> rtts;
    HistoricBuffer<double, 4> selfRtts;
    std::map<std::int64_t, double> udpPingTimes;
    double averageRTT;
    std::shared_ptr<NetworkSocket> socket;
    int udpPongCount;
    int totalUdpPings = 0;
    int totalUdpPingReplies = 0;
};

class AudioDevice
{
public:
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
    AudioInputTester(const std::string deviceID);
    ~AudioInputTester();
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(AudioInputTester);
    float GetAndResetLevel();
    bool Failed()
    {
        return io && io->Failed();
    }

private:
    void Update(std::int16_t* samples, std::size_t count);
    audio::AudioIO* io = nullptr;
    audio::AudioInput* input = nullptr;
    std::int16_t maxSample = 0;
    std::string deviceID;
};

class PacketSender;
namespace video
{
    class VideoPacketSender;
}

class VoIPController
{
    friend class VoIPGroupController;
    friend class PacketSender;

public:
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(VoIPController);
    struct Config
    {
        Config(double initTimeout = 30.0, double recvTimeout = 20.0, DataSaving dataSaving = DataSaving::NEVER, bool enableAEC = false, bool enableNS = false, bool enableAGC = false, bool enableCallUpgrade = false)
        {
            this->initTimeout = initTimeout;
            this->recvTimeout = recvTimeout;
            this->dataSaving = dataSaving;
            this->enableAEC = enableAEC;
            this->enableNS = enableNS;
            this->enableAGC = enableAGC;
            this->enableCallUpgrade = enableCallUpgrade;
        }

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

    VoIPController();
    virtual ~VoIPController();

    /**
		 * Set the initial endpoints (relays)
		 * @param endpoints Endpoints converted from phone.PhoneConnection TL objects
		 * @param allowP2p Whether p2p connectivity is allowed
		 * @param connectionMaxLayer The max_layer field from the phoneCallProtocol object returned by Telegram server.
		 * DO NOT HARDCODE THIS VALUE, it's extremely important for backwards compatibility.
		 */
    void SetRemoteEndpoints(std::vector<Endpoint> endpoints, bool allowP2p, std::int32_t connectionMaxLayer);
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
    /**
		 *
		 * @param mute
		 */
    virtual void SetMicMute(bool mute);
    /**
		 *
		 * @param key
		 * @param isOutgoing
		 */
    void SetEncryptionKey(char* key, bool isOutgoing);
    /**
		 *
		 * @param cfg
		 */
    void SetConfig(const Config& cfg);
    void DebugCtl(int request, int param);
    /**
		 *
		 * @param stats
		 */
    void GetStats(TrafficStats* stats);
    /**
		 *
		 * @return
		 */
    std::int64_t GetPreferredRelayID();
    /**
		 *
		 * @return
		 */
    Error GetLastError();
    /**
		 *
		 */
    static CryptoFunctions crypto;
    /**
		 *
		 * @return
		 */
    static const char* GetVersion();
    /**
		 *
		 * @return
		 */
    std::string GetDebugLog();
    /**
		 *
		 * @return
		 */
    static std::vector<AudioInputDevice> EnumerateAudioInputs();
    /**
		 *
		 * @return
		 */
    static std::vector<AudioOutputDevice> EnumerateAudioOutputs();
    /**
		 *
		 * @param id
		 */
    void SetCurrentAudioInput(std::string id);
    /**
		 *
		 * @param id
		 */
    void SetCurrentAudioOutput(std::string id);
    /**
		 *
		 * @return
		 */
    std::string GetCurrentAudioInputID();
    /**
		 *
		 * @return
		 */
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
    void SendGroupCallKey(unsigned char* key);
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
    void SetPersistentState(std::vector<std::uint8_t> state);

#if defined(TGVOIP_USE_CALLBACK_AUDIO_IO)
    void SetAudioDataCallbacks(std::function<void(std::int16_t*, std::size_t)> input, std::function<void(std::int16_t*, std::size_t)> output, std::function<void(std::int16_t*, std::size_t)> preprocessed);
#endif

    void SetVideoCodecSpecificData(const std::vector<Buffer>& data);

    struct Callbacks
    {
        void (*connectionStateChanged)(VoIPController*, State);
        void (*signalBarCountChanged)(VoIPController*, int);
        void (*groupCallKeySent)(VoIPController*);
        void (*groupCallKeyReceived)(VoIPController*, const unsigned char*);
        void (*upgradeToGroupCallRequested)(VoIPController*);
    };
    void SetCallbacks(Callbacks callbacks);

    float GetOutputLevel()
    {
        return 0.0f;
    }
    void SetVideoSource(video::VideoSource* source);
    void SetVideoRenderer(video::VideoRenderer* renderer);

    void SetInputVolume(float level);
    void SetOutputVolume(float level);
#if defined(__APPLE__) && defined(TARGET_OS_OSX)
    void SetAudioOutputDuckingEnabled(bool enabled);
#endif

    struct PendingOutgoingPacket
    {
        PendingOutgoingPacket(std::uint32_t seq, unsigned char type, std::size_t len, Buffer&& data, std::int64_t endpoint)
        {
            this->seq = seq;
            this->type = type;
            this->len = len;
            this->data = std::move(data);
            this->endpoint = endpoint;
        }
        PendingOutgoingPacket(PendingOutgoingPacket&& other)
        {
            seq = other.seq;
            type = other.type;
            len = other.len;
            data = std::move(other.data);
            endpoint = other.endpoint;
        }
        PendingOutgoingPacket& operator=(PendingOutgoingPacket&& other)
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
        TGVOIP_DISALLOW_COPY_AND_ASSIGN(PendingOutgoingPacket);
        std::uint32_t seq;
        unsigned char type;
        std::size_t len;
        Buffer data;
        std::int64_t endpoint;
    };

    struct Stream
    {
        std::int32_t userID;
        unsigned char id;
        unsigned char type;
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

private:
    struct UnacknowledgedExtraData;

protected:
    struct RecentOutgoingPacket
    {
        std::uint32_t seq;
        std::uint16_t id; // for group calls only
        double sendTime;
        double ackTime;
        std::uint8_t type;
        std::uint32_t size;
        PacketSender* sender;
        bool lost;
    };
    struct QueuedPacket
    {
        Buffer data;
        unsigned char type;
        HistoricBuffer<std::uint32_t, 16> seqs;
        double firstSentTime;
        double lastSentTime;
        double retryInterval;
        double timeout;
    };
    virtual void ProcessIncomingPacket(NetworkPacket& packet, Endpoint& srcEndpoint);
    virtual void ProcessExtraData(Buffer& data);
    virtual void WritePacketHeader(std::uint32_t seq, BufferOutputStream* s, unsigned char type, std::uint32_t length, PacketSender* source);
    virtual void SendPacket(unsigned char* data, std::size_t len, Endpoint& ep, PendingOutgoingPacket& srcPacket);
    virtual void SendInit();
    virtual void SendUdpPing(Endpoint& endpoint);
    virtual void SendRelayPings();
    virtual void OnAudioOutputReady();
    virtual void SendExtra(Buffer& data, unsigned char type);
    void SendStreamFlags(Stream& stream);
    void InitializeTimers();
    void ResetEndpointPingStats();
    void SendVideoFrame(const Buffer& frame, std::uint32_t flags, std::uint32_t rotation);
    void ProcessIncomingVideoFrame(Buffer frame, std::uint32_t pts, bool keyframe, std::uint16_t rotation);
    std::shared_ptr<Stream> GetStreamByType(int type, bool outgoing);
    std::shared_ptr<Stream> GetStreamByID(unsigned char id, bool outgoing);
    Endpoint* GetEndpointForPacket(const PendingOutgoingPacket& pkt);
    bool SendOrEnqueuePacket(PendingOutgoingPacket pkt, bool enqueue = true, PacketSender* source = nullptr);
    static std::string NetworkTypeToString(NetType type);
    CellularCarrierInfo GetCarrierInfo();

private:
    struct UnacknowledgedExtraData
    {
        unsigned char type;
        Buffer data;
        std::uint32_t firstContainingSeq;
    };
    struct RecentIncomingPacket
    {
        std::uint32_t seq;
        double recvTime;
    };
    enum
    {
        UDP_UNKNOWN = 0,
        UDP_PING_PENDING,
        UDP_PING_SENT,
        UDP_AVAILABLE,
        UDP_NOT_AVAILABLE,
        UDP_BAD
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

    void RunRecvThread();
    void RunSendThread();
    void HandleAudioInput(unsigned char* data, std::size_t len, unsigned char* secondaryData, std::size_t secondaryLen);
    void UpdateAudioBitrateLimit();
    void SetState(State state);
    void UpdateAudioOutputState();
    void InitUDPProxy();
    void UpdateDataSavingState();
    void KDF(unsigned char* msgKey, std::size_t x, unsigned char* aesKey, unsigned char* aesIv);
    void KDF2(unsigned char* msgKey, std::size_t x, unsigned char* aesKey, unsigned char* aesIv);
    void SendPublicEndpointsRequest();
    void SendPublicEndpointsRequest(const Endpoint& relay);
    Endpoint& GetEndpointByType(Endpoint::Type type);
    void SendPacketReliably(unsigned char type, unsigned char* data, std::size_t len, double retryInterval, double timeout);
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
    std::string GetPacketTypeString(unsigned char type);
    void SetupOutgoingVideoStream();
    bool WasOutgoingPacketAcknowledged(std::uint32_t seq);
    RecentOutgoingPacket* GetRecentOutgoingPacket(std::uint32_t seq);
    void NetworkPacketReceived(std::shared_ptr<NetworkPacket> packet);
    void TrySendQueuedPackets();

    State state;
    std::map<std::int64_t, Endpoint> endpoints;
    std::int64_t currentEndpoint = 0;
    std::int64_t preferredRelay = 0;
    std::int64_t peerPreferredRelay = 0;
    std::atomic<bool> runReceiver;
    std::atomic<std::uint32_t> seq;
    std::uint32_t lastRemoteSeq;
    std::uint32_t lastRemoteAckSeq;
    std::uint32_t lastSentSeq;
    std::vector<RecentOutgoingPacket> recentOutgoingPackets;
    std::vector<std::uint32_t> recentIncomingPackets;
    HistoricBuffer<std::uint32_t, 10, double> sendLossCountHistory;
    std::uint32_t audioTimestampIn;
    std::uint32_t audioTimestampOut;
    tgvoip::audio::AudioIO* audioIO = nullptr;
    tgvoip::audio::AudioInput* audioInput = nullptr;
    tgvoip::audio::AudioOutput* audioOutput = nullptr;
    OpusEncoder* encoder;
    std::vector<PendingOutgoingPacket> sendQueue;
    EchoCanceller* echoCanceller;
    std::atomic<bool> stopping;
    bool audioOutStarted;
    Thread* recvThread;
    Thread* sendThread;
    std::uint32_t packetsReceived;
    std::uint32_t recvLossCount;
    std::uint32_t prevSendLossCount;
    std::uint32_t firstSentPing;
    HistoricBuffer<double, 32> rttHistory;
    bool waitingForAcks;
    NetType networkType;
    int dontSendPackets;
    Error lastError;
    bool micMuted;
    std::uint32_t maxBitrate;
    std::vector<std::shared_ptr<Stream>> outgoingStreams;
    std::vector<std::shared_ptr<Stream>> incomingStreams;
    unsigned char encryptionKey[256];
    unsigned char keyFingerprint[8];
    unsigned char callID[16];
    double stateChangeTime;
    bool waitingForRelayPeerInfo;
    bool allowP2p;
    bool dataSavingMode;
    bool dataSavingRequestedByPeer;
    std::string activeNetItfName;
    double publicEndpointsReqTime;
    std::vector<QueuedPacket> queuedPackets;
    double connectionInitTime;
    double lastRecvPacketTime;
    Config config;
    std::int32_t peerVersion;
    CongestionControl* conctl;
    TrafficStats stats;
    bool receivedInit;
    bool receivedInitAck;
    bool isOutgoing;
    NetworkSocket* udpSocket;
    NetworkSocket* realUdpSocket;
    FILE* statsDump;
    std::string currentAudioInput;
    std::string currentAudioOutput;
    bool useTCP;
    bool useUDP;
    bool didAddTcpRelays;
    SocketSelectCanceller* selectCanceller;
    HistoricBuffer<unsigned char, 4, int> signalBarsHistory;
    bool audioStarted = false;

    int udpConnectivityState;
    double lastUdpPingTime;
    int udpPingCount;
    int echoCancellationStrength;

    Proxy proxyProtocol;
    std::string proxyAddress;
    std::uint16_t proxyPort;
    std::string proxyUsername;
    std::string proxyPassword;
    NetworkAddress resolvedProxyAddress = NetworkAddress::Empty();

    std::uint32_t peerCapabilities;
    Callbacks callbacks;
    bool didReceiveGroupCallKey;
    bool didReceiveGroupCallKeyAck;
    bool didSendGroupCallKey;
    bool didSendUpgradeRequest;
    bool didInvokeUpgradeCallback;

    std::int32_t connectionMaxLayer;
    bool useMTProto2;
    bool setCurrentEndpointToTCP;

    std::vector<UnacknowledgedExtraData> currentExtras;
    std::unordered_map<std::uint8_t, std::uint64_t> lastReceivedExtrasByType;
    bool useIPv6;
    bool peerIPv6Available;
    NetworkAddress myIPv6 = NetworkAddress::Empty();
    bool shittyInternetMode;
    int extraEcLevel = 0;
    std::vector<Buffer> ecAudioPackets;
    bool didAddIPv6Relays;
    bool didSendIPv6Endpoint;
    int publicEndpointsReqCount = 0;
    bool wasEstablished = false;
    bool receivedFirstStreamPacket = false;
    std::atomic<unsigned int> unsentStreamPackets;
    HistoricBuffer<unsigned int, 5> unsentStreamPacketsHistory;
    bool needReInitUdpProxy = true;
    bool needRate = false;
    std::vector<DebugLoggedPacket> debugLoggedPackets;
    BufferPool<1024, 32> outgoingAudioBufferPool;
    BlockingQueue<RawPendingOutgoingPacket> rawSendQueue;

    std::uint32_t initTimeoutID = MessageThread::INVALID_ID;
    std::uint32_t udpPingTimeoutID = MessageThread::INVALID_ID;

    effects::Volume outputVolume;
    effects::Volume inputVolume;

    std::vector<std::uint32_t> peerVideoDecoders;

    MessageThread messageThread;

    // Locked whenever the endpoints vector is modified (but not endpoints themselves) and whenever iterated outside of messageThread.
    // After the call is started, only messageThread is allowed to modify the endpoints vector.
    Mutex endpointsMutex;
    // Locked while audio i/o is being initialized and deinitialized so as to allow it to fully initialize before deinitialization begins.
    Mutex audioIOMutex;

#if defined(TGVOIP_USE_CALLBACK_AUDIO_IO)
    std::function<void(std::int16_t*, std::size_t)> audioInputDataCallback;
    std::function<void(std::int16_t*, std::size_t)> audioOutputDataCallback;
    std::function<void(std::int16_t*, std::size_t)> audioPreprocDataCallback;
    ::OpusDecoder* preprocDecoder = nullptr;
    std::int16_t preprocBuffer[4096];
#endif
#if defined(__APPLE__) && defined(TARGET_OS_OSX)
    bool macAudioDuckingEnabled = true;
#endif

    video::VideoSource* videoSource = nullptr;
    video::VideoRenderer* videoRenderer = nullptr;
    std::uint32_t lastReceivedVideoFrameNumber = std::numeric_limits<std::uint32_t>::max();

    video::VideoPacketSender* videoPacketSender = nullptr;
    std::uint32_t sendLosses = 0;
    std::uint32_t unacknowledgedIncomingPacketCount = 0;

    ProtocolInfo protocolInfo = {0};

    /*** debug report problems ***/
    bool wasReconnecting = false;
    bool wasExtraEC = false;
    bool wasEncoderLaggy = false;
    bool wasNetworkHandover = false;

    /*** persistable state values ***/
    bool proxySupportsUDP = true;
    bool proxySupportsTCP = true;
    std::string lastTestedProxyServer = "";

    /*** server config values ***/
    std::uint32_t maxAudioBitrate;
    std::uint32_t maxAudioBitrateEDGE;
    std::uint32_t maxAudioBitrateGPRS;
    std::uint32_t maxAudioBitrateSaving;
    std::uint32_t initAudioBitrate;
    std::uint32_t initAudioBitrateEDGE;
    std::uint32_t initAudioBitrateGPRS;
    std::uint32_t initAudioBitrateSaving;
    std::uint32_t minAudioBitrate;
    std::uint32_t audioBitrateStepIncr;
    std::uint32_t audioBitrateStepDecr;
    double relaySwitchThreshold;
    double p2pToRelaySwitchThreshold;
    double relayToP2pSwitchThreshold;
    double reconnectingTimeout;
    std::uint32_t needRateFlags;
    double rateMaxAcceptableRTT;
    double rateMaxAcceptableSendLoss;
    double packetLossToEnableExtraEC;
    std::uint32_t maxUnsentStreamPackets;
    std::uint32_t unackNopThreshold;

public:
#ifdef __APPLE__
    static double machTimebase;
    static std::uint64_t machTimestart;
#endif
#ifdef _WIN32
    static std::int64_t win32TimeScale;
    static bool didInitWin32TimeScale;
#endif
};

class VoIPGroupController : public VoIPController
{
public:
    VoIPGroupController(std::int32_t timeDifference);
    ~VoIPGroupController() override;
    void SetGroupCallInfo(unsigned char* encryptionKey, unsigned char* reflectorGroupTag, unsigned char* reflectorSelfTag, unsigned char* reflectorSelfSecret, unsigned char* reflectorSelfTagHash, std::int32_t selfUserID, NetworkAddress reflectorAddress, NetworkAddress reflectorAddressV6, std::uint16_t reflectorPort);
    void AddGroupCallParticipant(std::int32_t userID, unsigned char* memberTagHash, unsigned char* serializedStreams, std::size_t streamsLength);
    void RemoveGroupCallParticipant(std::int32_t userID);
    float GetParticipantAudioLevel(std::int32_t userID);
    void SetMicMute(bool mute) override;
    void SetParticipantVolume(std::int32_t userID, float volume);
    void SetParticipantStreams(std::int32_t userID, unsigned char* serializedStreams, std::size_t length);
    static std::size_t GetInitialStreams(unsigned char* buf, std::size_t size);

    struct Callbacks : public VoIPController::Callbacks
    {
        void (*updateStreams)(VoIPGroupController*, unsigned char*, std::size_t);
        void (*participantAudioStateChanged)(VoIPGroupController*, std::int32_t, bool);
    };
    void SetCallbacks(Callbacks callbacks);
    std::string GetDebugString() override;
    void SetNetworkType(NetType type) override;

protected:
    void ProcessIncomingPacket(NetworkPacket& packet, Endpoint& srcEndpoint) override;
    void SendInit() override;
    void SendUdpPing(Endpoint& endpoint) override;
    void SendRelayPings() override;
    void SendPacket(unsigned char* data, std::size_t len, Endpoint& ep, PendingOutgoingPacket& srcPacket) override;
    void WritePacketHeader(std::uint32_t seq, BufferOutputStream* s, unsigned char type, std::uint32_t length, PacketSender* sender = nullptr) override;
    void OnAudioOutputReady() override;

private:
    std::int32_t GetCurrentUnixtime();
    std::vector<std::shared_ptr<Stream>> DeserializeStreams(BufferInputStream& in);
    void SendRecentPacketsRequest();
    void SendSpecialReflectorRequest(unsigned char* data, std::size_t len);
    void SerializeAndUpdateOutgoingStreams();
    struct GroupCallParticipant
    {
        std::int32_t userID;
        unsigned char memberTagHash[32];
        std::vector<std::shared_ptr<Stream>> streams;
        AudioLevelMeter* levelMeter;
    };
    std::vector<GroupCallParticipant> participants;
    unsigned char reflectorSelfTag[16];
    unsigned char reflectorSelfSecret[16];
    unsigned char reflectorSelfTagHash[32];
    std::int32_t userSelfID;
    Endpoint groupReflector;
    AudioMixer* audioMixer;
    AudioLevelMeter selfLevelMeter;
    Callbacks groupCallbacks;
    struct PacketIdMapping
    {
        std::uint32_t seq;
        std::uint16_t id;
        double ackTime;
    };
    std::vector<PacketIdMapping> recentSentPackets;
    Mutex sentPacketsMutex;
    Mutex participantsMutex;
    std::int32_t timeDifference;
};

};

#endif
