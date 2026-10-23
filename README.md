# Do a Barrel Roll

Do a Barrel Roll is an open-source native mod for Minecraft Bedrock on Android, made for [LeviLauncher](https://github.com/LiteLDev/LeviLaunchroid).

## Features

- Full pitch, yaw, and roll control during elytra flight
- Adjustable banking, smoothing, sensitivity, and momentum steering
- Movable touch buttons, keyboard and controller support
- Client-side use in singleplayer and multiplayer
- Mod-menu settings with persistent configuration

## Requirements

- Android 9 or newer and a 64-bit ARM device (`arm64-v8a`)
- [LeviLauncher](https://github.com/LiteLDev/LeviLaunchroid) to load the mod
- Minecraft Bedrock **26.52**

## Installation

1. Install LeviLauncher.
2. Import `DoABarrelRoll.levipack` through the launcher's mod manager and enable it.
3. Launch Minecraft through LeviLauncher.

## Build

Requires Android NDK r28c, xmake, and Python 3.

```sh
xmake f -c -y -p android -a arm64-v8a -m release --toolchain=ndk --runtimes=c++_shared --ndk=/path/to/android-ndk-r28c --ndk_sdkver=28
xmake -y
```

The build produces `bin/DoABarrelRoll.so` and `bin/DoABarrelRoll.levipack`.

## Credits

The Android mod is based on [Do-A-Barrel-Roll-Bedrock](https://github.com/theaddonn/Do-A-Barrel-Roll-Bedrock) by **theaddonn**.

## License

Do a Barrel Roll is licensed under the [GNU General Public License v3.0](LICENSE).
