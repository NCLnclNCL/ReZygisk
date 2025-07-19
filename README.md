# WARNING

This fork is primarily intended for my own personal use.
It is in no way affiliated with, approved by or supported by PerformanC or ThePedroo.

Note that, on one hand, this fork is what I use on my daily driver phone, so it is in my best
interest for it to be stable and properly tested. On the other hand, I am unlikely to put any
effort into fixing issues that do not manifest on any of my devices, and as such, I cannot
recommend that you flash this module on your device.

# Fork info

The majority of changes in this fork aim to demonstrate unique approaches to hiding root from applications.
In addition, there are some changes to make the module better align with my personal preferences.

## Options

The below options are on/off, and turning them on is done by creating an empty file in `/data/adb/nrezygisk`
with the appropriate name. The options are:

- `clean_zygote`: Run zygote in a clean mount namespace (as in, free of suspicious mounts).
  - This mitigates `Futile Hide (08)` of Native Test, and `Inconsistent Mount` of NT and Holmes.
  - It might also fix other detections, such as the magic mount detection used by Native Detector prior to
  version v7.2.0.
  - This option is enabled by default, and is not meant to be disabled except for debugging.
- `private_mounts`: Make suspicious mounts private.
  - This mitigates `Evil Modification (4)` of Holmes, `Mount Inconsistency` of Native Detector,
  and `Abnormal Environment` of Native Test. (But note that `Abnormal Environment` in NT can also be caused
  by other detections, one is described below in Limitations.)
  - In some cases, this option might cause some mounts to not be present due to how it affects mount propagation.
  - In some cases, this option might not be able to mitigate these detections, particularly on Magisk 
  where some mounts are placed too early.
  - This option requires `clean_zygote` to be enabled for proper operation.
  - This option is disabled by default.
- `inject_init`: Instead of using `PTRACE_O_TRACEFORK`, inject code into `init` (pid 1) that allows
us to monitor `fork()` calls of `init` and attach to its child processes.
  - The primary motivation is to avoid a `ptrace_message`-based detection (described [here](https://github.com/PerformanC/ReZygisk/issues/171)).
  - But note that even with this option disabled, this detection should be fixed by a `PTRACE_SYSCALL`-based
  mitigation for newer kernels, and a `PTRACE_O_TRACESECCOMP`-based mitigation for older kernels.
  These two mitigations (but not the `init` injection) are also included in upstream ReZygisk.
  - So currently this option is not required for hiding purposes, but it provides us an alternative method
  in case an existing mitigation proves to be problematic.
  - Using this option lets us detach from `init` after we finished injecting our code, allowing others to
  attach to `init`. (Only one process can attach with `ptrace` to a tracee at a time, so without this option,
  other modules are unable to trace `init`.)
  - If this option is enabled and injecting fails, the `bad_init_inject` file will be created,
  which disables the `inject_init` option to avoid bootloops.
  - This option is disabled by default.
- `zygote_dlopen`: Load modules in Zygote rather than only after forking.
  - This might save a little bit of CPU and RAM, and it allows modules to run code in Zygote.
  - It might break modules that don't expect this to happen.
  - This option is not related to hiding root.
  - This option is disabled by default.

In addition, it is possible to change denylisted apps and unmounted mountpoints using the file `/data/adb/nrezygisk/rules.txt`:
- Lines starting with `/` are interpreted as mountpoints to unmount, e.g. `/data/adb/*`
- Other lines are interpreted as apps
  - This can be a package name like `com.termux` or `com.google.*`
  - Or an uid like `10123`
  - Or an uid range like `0-9999` or `10000-*`
  - By default, apps here will be added to the denylist, `-` can be used to remove from denylist, e.g. `-com.termux` or `-10123`
  - Rules are processed in the order they are listed, only the first matching rule has effect
  - These rules override the denylist status specified by the root implementation, except that apps granted root will never be denylisted
- Note that `*` works as a wildcard only when it's the last character of a line

## Limitations

- My goal was to mitigate the detections that arise as a result of root, especially KernelSU (but also tested on APatch and Magisk).
  - It was not a goal to hide traces caused by the use of a custom ROM or custom kernel, as I do not use those.
  - Modules might also leave traces, which might show up as detections like `Futile Hide (02)`.
  - In general, it is nearly impossible to completely hide modules that inject themselves into an app
  and then do not unload themselves, which is the case e.g. when an LSPosed module is active for a given app.
- Some detections cannot be properly fixed by user space modules. One example is the detection of syscall abnormalities
caused by KernelSU and APatch. This shows up as `Root Indicator / delayed syscall` in Native Detector,
and as `Abnormal Environment` in Native Test and Holmes.
  - For KernelSU, some possible fixes are to disable sucompat
  (which means that `/system/bin/su` will not work, so apps won't be able to use root), or to use manual hooks
  (which requires the patching and compilation of the kernel source code).
  - The solution I use myself is one I devised, which is to replace the sucompat kprobes of KernelSU
  with a `/system/bin/su` binary that is mounted by the built-in module mounting system of KernelSU.
  Unlike manual hooks, this also works in LKM mode and does not require compiling the kernel.
  More details [here](https://github.com/nampud/KernelSU/releases/tag/v0.0.3).

(The above is not a complete list of limitations)

# ReZygisk

[Bahasa Indonesia](/READMEs/README_id-ID.md)|[Tiếng Việt](/READMEs/README_vi-VN.md)|[Português Brasileiro](/READMEs/README_pt-BR.md)|[French](/READMEs/README_fr-FR.md)|[日本語](/READMEs/README_ja-JP.md)

ReZygisk is a fork of Zygisk Next, a standalone implementation of Zygisk, providing Zygisk API support for KernelSU, APatch and Magisk (Official and Kitsune).

It aims to modernize and re-write the codebase to C entirely, allowing a more efficient and faster implementation of the Zygisk API with a more permissive, and FOSS friendly, license.

## Why?

The latest releases of Zygisk Next are not open-source, reserving entirely the code for its developers. Not only does that limit our ability to contribute to the project, but also impossibilities the audit of the code, which is a major security concern, as Zygisk Next is a module that runs with superuser (root) privileges, having access to the entire system.

The Zygisk Next developers are famous and trusted in the Android community, however, this doesn't mean that the code is not malicious or vulnerable. We (PerformanC) understand they have their reasons to keep the code closed-source, but we believe the contrary.

## Advantages

- FOSS (Forever)

## Dependencies

| Tool            | Description                            |
|-----------------|----------------------------------------|
| `Android NDK`   | Native Development Kit for Android     |

### C++ Dependencies

| Dependency | Description                   |
|------------|-------------------------------|
| `lsplt`    | Simple PLT Hook for Android   |

## Installation

### 1. Select the right zip

The selection of the build/zip is important, as it will determine how hidden and stable ReZygisk will be. This, however, is not a hard task:

- `release` should be the one chosen for most cases, it removes app-level logging and offers more optimized binaries.
- `debug`, however, offers the opposite, with heavy logging and no optimizations, For this reason, **you should only use it for debugging purposes** and **when obtaining logs for creating an Issue**.

As for branches, you should always use the `main` branch, unless told otherwise by the developers, or if you want to test upcoming features and are aware of the risks involved.

### 2. Flash the zip

After choosing the right build, you should flash it using your current root manager, like Magisk or KernelSU. You can do this by going to the `Modules` section of your root manager and selecting the zip you downloaded.

After flashing, check the installation logs to ensure there are no errors, and if everything is fine, you can reboot your device.

> [!WARNING]
> Magisk users should disable built-in Zygisk, as it will conflict with ReZygisk. This can be done by going to the `Settings` section of Magisk and disabling the `Zygisk` option.

### 3. Verify the installation

After rebooting, you can verify if ReZygisk is working properly by checking the module description in the `Modules` section of your root manager. The description should indicate that the necessary daemons are running. For example, if your environment supports both 64-bit and 32-bit, it should look similar to this: `[monitor: 😋 tracing, zygote64: 😋 injected, daemon64: 😋 running (...) zygote32: 😋 injected, daemon32: 😋 running (...)] Standalone implementation of Zygisk.`

## Translation

There are currently two different ways to contribute translations for ReZygisk:

- For translations of the README, you can create a new file in the `READMEs` folder, following the naming convention of `README_<language>.md`, where `<language>` is the language code (e.g., `README_pt-BR.md` for Brazilian Portuguese), and open a pull request to the `main` branch with your changes.
- For translations of the ReZygisk WebUI, you should first contribute to our [Crowdin](https://crowdin.com/project/rezygisk). Once approved retrieve the `.json` file from there and open a pull request with your changes -- adding the `.json` file to the `webroot/lang` folder and your credits to the `TRANSLATOR.md` file, in alphabetic order.

## Support

For any question related to ReZygisk or other PerformanC projects, feel free to join any of the following channels below:

- Discord Channel: [PerformanC](https://discord.gg/uPveNfTuCJ)
- ReZygisk Telegram Channel: [@rezygisk](https://t.me/rezygisk)
- PerformanC Telegram Channel: [@performancorg](https://t.me/performancorg)
- PerformanC Signal Group: [@performanc](https://signal.group/#CjQKID3SS8N5y4lXj3VjjGxVJnzNsTIuaYZjj3i8UhipAS0gEhAedxPjT5WjbOs6FUuXptcT)

## Contribution

It is mandatory to follow PerformanC's [Contribution Guidelines](https://github.com/PerformanC/contributing) to contribute to ReZygisk. Following its Security Policy, Code of Conduct, and syntax standard.

## License

ReZygisk is licensed majoritaly under GPL, by Dr-TSNG, but also AGPL 3.0, by The PerformanC Organization, for re-written code. You can read more about it on [Open Source Initiative](https://opensource.org/licenses/AGPL-3.0).
