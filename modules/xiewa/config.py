def can_build(env, platform):
    # xiewa_guard2d 依赖 VirtualQuery / ReadProcessMemory / GetSystemFirmwareTable，
    # 且 xiewa_guard2d.cpp 在非 Windows 下直接 #error，所以只在 Windows 编。
    return platform == "windows"


def configure(env):
    pass
