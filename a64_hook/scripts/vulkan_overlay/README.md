# a64_hook Vulkan Overlay

Proof-of-concept Vulkan HUD overlay that integrates with the `a64_hook`
kernel module via `liba64hook`.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  vulkan_overlay                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌─────────────────┐  │
│  │ Vulkan Init  │──▶│ GPU Pipeline │──▶│ Swapchain/Output│  │
│  └──────────────┘   └──────┬───────┘   └─────────────────┘  │
│                            │                                 │
│  ┌──────────────┐          │ query stats every frame         │
│  │ liba64hook   │──────────┘                                 │
│  └──────┬───────┘                                            │
│         │ ioctl                                               │
│  ┌──────┴───────┐                                            │
│  │ a64_hook.ko  │  (kernel module)                           │
│  └──────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
```

- **vulkan_overlay.c** — Main program: initializes Vulkan, sets up a
  graphics pipeline, and runs a frame loop.
- **liba64hook** — Userspace library (`../liba64hook.h`) that communicates
  with the `a64_hook.ko` kernel module via ioctl.
- **a64_hook.ko** — ARM64 inline hook engine kernel module.

## Build

### Linux (desktop proof-of-concept)

```bash
# Install Vulkan SDK (Ubuntu/Debian)
sudo apt install libvulkan-dev vulkan-tools

# Build
make
./vulkan_overlay
```

### Android cross-compile

```bash
# Set NDK path (or edit Makefile)
export ANDROID_NDK=$HOME/Android/Sdk/ndk/27.0.12077973

# Cross-compile
make android

# Push to device
adb push vulkan_overlay.arm64 /data/local/tmp/
adb shell chmod +x /data/local/tmp/vulkan_overlay.arm64

# Load kernel module first
adb push ../a64_hook.ko /data/local/tmp/
adb shell su -c "insmod /data/local/tmp/a64_hook.ko"

# Run overlay
adb shell /data/local/tmp/vulkan_overlay.arm64
```

## Requirements

- Linux or Android device with Vulkan 1.0+ support
- `a64_hook.ko` kernel module loaded
- liba64hook userspace library compiled for target
- Vulkan SDK (for actual GPU rendering) or VOLK

## Headless / Demo Mode

Compiling without the Vulkan SDK produces a headless binary that prints
hook statistics to the terminal instead of rendering to a GPU surface.
This is useful for testing the liba64hook integration on systems without
Vulkan drivers (e.g., CI pipelines, early development).

## Output

The overlay displays:
- Global hook statistics (uptime, total hooks, total hits)
- DMA/cache operation counters
- Per-hook entries: name, type (detour/kprobe/DMA), state, hit count
- Frame counter (updated at ~10 fps)

## Extending

To add actual GPU rendering:
1. Include `volk.h`/`volk.c` for function loading
2. Implement `vkCreateSwapchainKHR` for display output
3. Add a font atlas (e.g., stb_truetype) for text rendering
4. Replace `render_overlay_text()` with actual Vulkan draw calls
5. Use push constants or a UBO to pass hook data to shaders

## License

GPL v2 (same as a64_hook kernel module).
