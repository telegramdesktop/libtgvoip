//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#ifndef TGVOIP_SAMPLEBUFFERDISPLAYLAYERRENDERER
#define TGVOIP_SAMPLEBUFFERDISPLAYLAYERRENDERER

#include "../../video/VideoRenderer.h"
#include <VideoToolbox/VideoToolbox.h>
#include <objc/objc.h>
#include <vector>

#ifdef __OBJC__
@class TGVVideoRenderer;
#else
typedef struct objc_object TGVVideoRenderer;
#endif

namespace tgvoip
{
namespace video
{
    class SampleBufferDisplayLayerRenderer : public VideoRenderer
    {
    public:
        SampleBufferDisplayLayerRenderer(TGVVideoRenderer* renderer);
        virtual ~SampleBufferDisplayLayerRenderer();
        virtual void Reset(std::uint32_t codec, unsigned int width, unsigned int height, std::vector<Buffer>& csd) override;
        virtual void DecodeAndDisplay(Buffer frame, std::uint32_t pts) override;
        virtual void SetStreamEnabled(bool enabled) override;
        virtual void SetRotation(std::uint16_t rotation) override;
        virtual void SetStreamPaused(bool paused) override;
        static int GetMaximumResolution();
        static std::vector<std::uint32_t> GetAvailableDecoders();

    private:
        TGVVideoRenderer* renderer;
        CMFormatDescriptionRef formatDesc = NULL;
        bool needReset = false;
        bool streamEnabled = false;
    };
}
}

#endif /* TGVOIP_SAMPLEBUFFERDISPLAYLAYERRENDERER */
