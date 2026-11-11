# Community download site

Static site for `https://oxfuzz.bionicloud.net`. It introduces the app, links the
source repository on GitHub and invites contributions; downloads are hosted here.
The GitHub links assume the repository is public.
A small same-origin script controls the icon theme switch and screenshot gallery.
No accounts, tracking, remote fonts or build dependencies. Theme defaults to System
and is saved locally when browser storage is available. Screenshots show the
approved synthetic qualification fixture, not customer projects or benchmarks.

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

After each deployment, verify anonymous HTTPS downloads and their SHA-256 digests. Keep source, runtime data, SSH keys and GitHub credentials
outside the web root. Retain the previous deployment for rollback.

Sanitized, versioned release-qualification records live in `src/acceptance/` and
are copied with the site. Keep their bytes stable: the GitHub release records
reference their public URLs and SHA-256 digests. Do not copy raw runtime logs,
databases, provider configuration or credentials into that directory.
