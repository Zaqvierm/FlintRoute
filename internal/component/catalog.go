package component

import "fmt"

const (
	githubReleaseAPIHost = "api.github.com"
	githubAssetHost      = "github.com"
)

func SupportedCatalog() map[Kind]Release {
	return map[Kind]Release{
		KindXray: {
			Kind: KindXray, Version: "v26.3.27", Source: "https://github.com/XTLS/Xray-core",
			ReleaseAPI: "https://api.github.com/repos/XTLS/Xray-core/releases/latest", MinimumFreeByte: 64 << 20,
			Assets: []Asset{{
				Architecture: "arm64", PackageType: "zip",
				URL:    "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-arm64-v8a.zip",
				SHA256: "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c", Size: 19716427, Member: "xray",
			}},
		},
		KindZapret: {
			Kind: KindZapret, Version: "v72.13", Source: "https://github.com/bol-van/zapret",
			ReleaseAPI: "https://api.github.com/repos/bol-van/zapret/releases/latest", MinimumFreeByte: 24 << 20,
			Assets: []Asset{{
				Architecture: "arm64", PackageType: "tar.gz",
				URL:    "https://github.com/bol-van/zapret/releases/download/v72.13/zapret-v72.13-openwrt-embedded.tar.gz",
				SHA256: "b2a9f454523264899e0e7ba19c662e59e29fb20ebb354aa3631cd76885f4c2e6", Size: 3489340,
				BinarySHA256: "75fc3d6352eb9ebf510dfa470797c5ea079c475755ae3c0a79b1e9aaaf0c37a6",
				Member:       "zapret-v72.13/binaries/linux-arm64/nfqws",
			}},
		},
		KindTGWS: {
			Kind: KindTGWS, Version: "0.9.3-rev2", Source: "https://github.com/spatiumstas/tg-ws-proxy-go",
			ReleaseAPI: "https://api.github.com/repos/spatiumstas/tg-ws-proxy-go/releases/latest", MinimumFreeByte: 12 << 20,
			Assets: []Asset{
				{Architecture: "aarch64_cortex-a53", PackageType: "ipk", URL: "https://github.com/spatiumstas/tg-ws-proxy-go/releases/download/0.9.3-rev2/tg-ws-proxy_0.9.3-2_openwrt_aarch64_cortex-a53.ipk", SHA256: "ec07accd771d69e1bf5bc173d08d60efa5905c55dc4ce4cdc1c09a9fef898a17", Size: 1802236},
				{Architecture: "aarch64_generic", PackageType: "ipk", URL: "https://github.com/spatiumstas/tg-ws-proxy-go/releases/download/0.9.3-rev2/tg-ws-proxy_0.9.3-2_openwrt_aarch64_generic.ipk", SHA256: "063a426115882e89c50e8e95cca97bb6a12b2aaccf08d4270eb65429cd493693", Size: 1802229},
			},
		},
	}
}

func SelectAsset(release Release, platform Platform) (Asset, error) {
	if release.Kind == KindTGWS {
		for _, packageArch := range platform.PackageArchitectures {
			for _, asset := range release.Assets {
				if asset.Architecture == packageArch {
					return asset, nil
				}
			}
		}
	}
	for _, asset := range release.Assets {
		if asset.Architecture == platform.GOARCH {
			return asset, nil
		}
	}
	return Asset{}, fmt.Errorf("%s %s has no pinned asset for architecture %s", release.Kind, release.Version, platform.GOARCH)
}
