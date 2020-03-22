//
// Created by Grishka on 10.08.2018.
//

#ifndef LIBTGVOIP_VIDEOSOURCE_H
#define LIBTGVOIP_VIDEOSOURCE_H

#include "../Buffers.h"
#include <functional>
#include <memory>
#include <cstdint>
#include <string>
#include <vector>

namespace tgvoip
{

namespace video
{

class VideoSource
{
public:
    using CallbackType = std::function<void(const Buffer& buffer, std::uint32_t flags, std::uint32_t m_rotation)>;

    virtual ~VideoSource() = default;

    static std::shared_ptr<VideoSource> Create();
    static std::vector<std::uint32_t> GetAvailableEncoders();

    void SetCallback(CallbackType callback);
    void SetStreamStateCallback(std::function<void(bool)> callback);

    virtual void Start() = 0;
    virtual void Stop() = 0;
    virtual void Reset(std::uint32_t codec, int maxResolution) = 0;
    virtual void RequestKeyFrame() = 0;
    virtual void SetBitrate(std::uint32_t bitrate) = 0;

    bool Failed() const;
    std::string GetErrorDescription() const;
    std::vector<Buffer>& GetCodecSpecificData();
    unsigned int GetFrameWidth() const;
    unsigned int GetFrameHeight() const;
    void SetRotation(unsigned int rotation);

protected:
    CallbackType m_callback;
    std::function<void(bool)> m_streamStateCallback;
    std::string m_error;
    std::vector<Buffer> m_csd;
    unsigned int m_width = 0;
    unsigned int m_height = 0;
    unsigned int m_rotation = 0;
    bool m_failed = false;
};

} // namespace video

} // namespace tgvoip

#endif // LIBTGVOIP_VIDEOSOURCE_H
