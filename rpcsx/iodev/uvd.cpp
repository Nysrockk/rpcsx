#include "orbis/IoDevice.hpp"
#include "orbis/KernelAllocator.hpp"
#include "orbis/file.hpp"
#include "orbis/thread/Thread.hpp"
#include "orbis/utils/Logs.hpp"

struct UVDFile : orbis::File {};

static orbis::ErrorCode uvd_ioctl(orbis::File *file, std::uint64_t request,
                                  void *argp, orbis::Thread *thread) {

  switch (request) {
  case 0x4004830b:
    // UVD version/capability query - return a reasonable value
    // This appears to be asking for UVD capabilities or version
    *reinterpret_cast<std::uint32_t *>(argp) = 0x600;  // Similar to VCE's 0x700
    ORBIS_LOG_WARNING("UVD ioctl 0x4004830b - returning stub capability value 0x600");
    return {};

  default:
    ORBIS_LOG_FATAL("Unhandled uvd ioctl", request);
    thread->where();
    return {};
  }
}

static const orbis::FileOps fileOps = {
    .ioctl = uvd_ioctl,
};

struct UVDDevice : orbis::IoDevice {
  orbis::ErrorCode open(rx::Ref<orbis::File> *file, const char *path,
                        std::uint32_t flags, std::uint32_t mode,
                        orbis::Thread *thread) override {
    auto newFile = orbis::knew<UVDFile>();
    newFile->ops = &fileOps;
    newFile->device = this;

    *file = newFile;
    return {};
  }
};

orbis::IoDevice *createUVDCharacterDevice() { return orbis::knew<UVDDevice>(); }
