#ifndef __TGVOIP_H
#define __TGVOIP_H

#include <functional>
#include <memory>
#include <string>
#include <vector>

struct TgVoipProxy
{
    std::string host;
    std::uint16_t port;
    std::string login;
    std::string password;
};

enum class TgVoipEndpointType
{
    Inet,
    Lan,
    UdpRelay,
    TcpRelay
};

struct TgVoipEdpointHost
{
    std::string ipv4;
    std::string ipv6;
};

struct TgVoipEndpoint
{
    std::int64_t endpointId;
    TgVoipEdpointHost host;
    std::uint16_t port;
    TgVoipEndpointType type;
    unsigned char peerTag[16];
};

enum class TgVoipNetworkType
{
    Unknown,
    Gprs,
    Edge,
    ThirdGeneration,
    Hspa,
    Lte,
    WiFi,
    Ethernet,
    OtherHighSpeed,
    OtherLowSpeed,
    OtherMobile,
    Dialup
};

enum class TgVoipDataSaving
{
    Never,
    Mobile,
    Always
};

struct TgVoipPersistentState
{
    std::vector<std::uint8_t> value;
};

#ifdef TGVOIP_USE_CUSTOM_CRYPTO
struct TgVoipCrypto
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
#endif

struct TgVoipConfig
{
    double initializationTimeout;
    double receiveTimeout;
    TgVoipDataSaving dataSaving;
    bool enableP2P;
    bool enableAEC;
    bool enableNS;
    bool enableAGC;
    bool enableCallUpgrade;
#ifndef _WIN32
    std::string logPath;
#else
    std::wstring logPath;
#endif
    int maxApiLayer;
};

struct TgVoipEncryptionKey
{
    std::vector<std::uint8_t> value;
    bool isOutgoing;
};

enum class TgVoipState
{
    WaitInit,
    WaitInitAck,
    Estabilished,
    Failed,
    Reconnecting
};

struct TgVoipTrafficStats
{
    std::uint64_t bytesSentWifi;
    std::uint64_t bytesReceivedWifi;
    std::uint64_t bytesSentMobile;
    std::uint64_t bytesReceivedMobile;
};

struct TgVoipFinalState
{
    TgVoipPersistentState persistentState;
    std::string debugLog;
    TgVoipTrafficStats trafficStats;
    bool isRatingSuggested;
};

struct TgVoipAudioDataCallbacks
{
    std::function<void(std::int16_t*, std::size_t)> input;
    std::function<void(std::int16_t*, std::size_t)> output;
    std::function<void(std::int16_t*, std::size_t)> preprocessed;
};

class TgVoip
{
protected:
    TgVoip() = default;

public:
    static void setLoggingFunction(std::function<void(std::string const&)> loggingFunction);
    static void setGlobalServerConfig(std::string const& serverConfig);
    static int getConnectionMaxLayer();
    static std::string getVersion();
    static TgVoip* makeInstance(
        TgVoipConfig const& config,
        TgVoipPersistentState const& persistentState,
        std::vector<TgVoipEndpoint> const& endpoints,
        std::unique_ptr<TgVoipProxy> const& proxy,
        TgVoipNetworkType initialNetworkType,
        TgVoipEncryptionKey const& encryptionKey
#ifdef TGVOIP_USE_CUSTOM_CRYPTO
        ,
        TgVoipCrypto const& crypto
#endif
#ifdef TGVOIP_USE_CALLBACK_AUDIO_IO
        ,
        TgVoipAudioDataCallbacks const& audioDataCallbacks
#endif
    );

    virtual ~TgVoip();

    virtual void setNetworkType(TgVoipNetworkType networkType) = 0;
    virtual void setMuteMicrophone(bool muteMicrophone) = 0;
    virtual void setAudioOutputGainControlEnabled(bool enabled) = 0;
    virtual void setEchoCancellationStrength(int strength) = 0;

    virtual std::string getLastError() = 0;
    virtual std::string getDebugInfo() = 0;
    virtual std::int64_t getPreferredRelayId() = 0;
    virtual TgVoipTrafficStats getTrafficStats() = 0;
    virtual TgVoipPersistentState getPersistentState() = 0;

    virtual void setOnStateUpdated(std::function<void(TgVoipState)> onStateUpdated) = 0;
    virtual void setOnSignalBarsUpdated(std::function<void(int)> onSignalBarsUpdated) = 0;

    virtual TgVoipFinalState stop() = 0;
};

#endif
