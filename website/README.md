# Community download site

Static site for `https://oxfuzz.bionicloud.net`, independent of GitHub visibility.
No production JavaScript, accounts, tracking, remote fonts or build dependencies.

```sh
cd website
npm test
npm run build -- --preview
python3 -m http.server 8094 --bind 127.0.0.1 --directory dist
```

Publication requires every package listed in `release.mjs`, including the sandbox
kit. Put the reviewed release assets in a separate directory and run:

```sh
npm run build -- --artifacts /absolute/path/to/release-assets
```

The build hashes actual files and rejects missing, empty or unsupported packages.
It generates same-origin download links, `release.json` and `SHA256SUMS.txt`.
Never deploy the preview as a published release. It has no package links.

Deploy the completed `dist/` into a new directory below `/srv/oxfuzz/releases/`.
Verify its hashes, then atomically replace the `/srv/oxfuzz/current` symlink.
`nginx.conf` is the initial HTTP virtual host; Certbot manages the production TLS
configuration. Do not replace Certbot's generated configuration with this template
on subsequent deployments. Existing unrelated virtual hosts must be preserved.

Before making the source repository private, verify anonymous HTTPS downloads and
their SHA-256 digests. Keep source, runtime data, SSH keys and GitHub credentials
outside the web root. Retain the previous deployment for rollback.
