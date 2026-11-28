# AxisGSI Android compatibility work

This branch starts a compatibility investigation for the existing AxisGSI APK. The goal is to preserve the original game/application behavior while determining what prevents it from installing or running on modern Android, including Android 16.

## Important distinction

AxisGSI is an APK application, not a GSI system image. A GSI is a generic Android system image; it still relies on the device's kernel, vendor implementation, and required hardware interfaces. An APK does not replace or bypass the vendor partition.

## Initial APK inspection

The supplied APK was unpacked for a first-pass inspection:

- The package namespace found in its DEX strings is `me.pou.app`.
- Its resources and strings identify it as a Pou-derived game with AxisGSI branding/content.
- The APK contains native libraries under `armeabi`, `armeabi-v7a`, and `x86`; no `arm64-v8a` library was present in the inspected archive.
- The app contains one DEX file.

These observations do not establish that the app is incompatible with Android 16. In particular, 32-bit ARM support depends on the target device/system image. The next audit workflow decodes the manifest and records the SDK declarations and ABI folders.

## First step: reproducible APK audit

Run **Actions → AxisGSI Android 16 Compatibility Audit → Run workflow**. The workflow downloads the APK, decodes its manifest with Apktool, and publishes a small audit artifact.

## Compatibility work plan

1. Record the exact manifest values, permissions, components, and native ABIs.
2. Test installation and launch on Android 16 on a device/system that supports 32-bit ARM apps.
3. Capture the actual Package Manager or runtime failure before changing the APK.
4. Only then patch the specific blocker, rebuild, sign with a new test key, and test again.

Changing `targetSdkVersion` alone is not a compatibility fix. Re-signing also means the modified APK will not update an installation signed with the original developer key.
