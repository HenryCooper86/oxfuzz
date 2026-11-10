export const version = "0.9.4";
export const packages = [
  {
    name: `oxfuzz_${version}_aarch64.dmg`,
    platform: "macOS",
    label: "Apple silicon",
    format: "DMG",
  },
  {
    name: `oxfuzz_${version}_x64.dmg`,
    platform: "macOS",
    label: "Intel",
    format: "DMG",
  },
  {
    name: `oxfuzz_${version}_amd64.AppImage`,
    platform: "Linux",
    label: "AppImage",
    format: "x86_64",
  },
  {
    name: `oxfuzz_${version}_amd64.deb`,
    platform: "Linux",
    label: "Debian / Ubuntu",
    format: "DEB",
  },
  {
    name: `oxfuzz-${version}-1.x86_64.rpm`,
    platform: "Linux",
    label: "Fedora / RHEL",
    format: "RPM",
  },
  {
    name: `oxfuzz_${version}_x64_en-US.msi`,
    platform: "Windows",
    label: "Installer",
    format: "MSI · x64",
  },
  {
    name: `oxfuzz_${version}_x64-setup.exe`,
    platform: "Windows",
    label: "Setup",
    format: "EXE · x64",
  },
  {
    name: `oxfuzz-sandbox-kit-${version}.tar.gz`,
    platform: "Sandbox",
    label: "Sandbox build kit",
    format: "TAR.GZ",
  },
];

export function validateRelease(release) {
  if (
    !release ||
    release.version !== version ||
    !Array.isArray(release.assets) ||
    release.assets.length === 0
  ) {
    throw new Error("A supported version and verified assets are required");
  }
  const names = new Set();
  return release.assets.map((asset) => {
    if (
      !packages.some((item) => item.name === asset.name) ||
      names.has(asset.name) ||
      !Number.isSafeInteger(asset.size) ||
      asset.size <= 0 ||
      !/^[a-f0-9]{64}$/.test(asset.sha256)
    ) {
      throw new Error("Invalid or duplicate release asset");
    }
    names.add(asset.name);
    return {
      name: asset.name,
      size: asset.size,
      sha256: asset.sha256,
      url: `/downloads/v${version}/${asset.name}`,
    };
  });
}
