# Community download site

Static site for `https://oxfuzz.bionicloud.net`. It introduces the app, links the
source repository on GitHub and invites contributions; downloads are hosted here.
The GitHub links assume the repository is public.
Small same-origin scripts control the theme switch, the step gallery and motion.
No accounts, tracking, remote fonts or build dependencies. Theme defaults to System
and is saved locally when browser storage is available.

The page is published in English (`/`) and Simplified Chinese (`/zh/`) from one
template, `src/index.html`. Every visible string lives in `locales.mjs`; the build
fails on a missing or unused key, and a test keeps the two languages in step.

The screenshots and the recording in `src/screenshots/` come from a real session
on the bundled examples (`examples/utf8_decoder`, `examples/cmake_tlv_lib`), and
the numbers on the page are the ones that session produced. Retake them together
if the app's look changes. Motion (`src/motion.js`) is skipped entirely when the
visitor asks for reduced motion, and the recording is replaced by a still.

The GUI demos in `src/demos/` are screen recordings of the released desktop app,
cut by `scripts/demo/cut_demo.py` from an edit spec: segments kept in order,
waits sped up with an on-screen "N x faster" badge, and one WebVTT file per
language whose cues say what each segment shows. The macOS clips (setup,
campaign, binary) were recorded on 2026-11-25 with an isolated copy of the app
(its own bundle id, `HF_APP_DIR` and `HF_CONFIG_DIR`) on sample projects in
`/Users/Shared/oxfuzz-demo`, so no personal paths or projects appear. The kernel
clip comes from the manual `gui-demo-kvm.yml` workflow, which drives the Linux
app on a KVM runner. Before publishing a retake, look at every frame of the cut
for other windows, file pickers or paths that are not the sample's. The build
fails if a page points at a demo file that `src/demos/` does not have.

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
Upload with `rsync -a --checksum --link-dest=/srv/oxfuzz/current/`. Every build
rewrites every file with a new modification time, so without `--checksum` an
unchanged file is copied with a new time, its ETag changes, and every returning
visitor downloads the whole page again (the site sends `Cache-Control: no-cache`).
With it, unchanged files are hard-linked to the live ones and keep their ETags.
`nginx.conf` is the initial HTTP virtual host; Certbot manages the production TLS
configuration. Do not replace Certbot's generated configuration with this template
on subsequent deployments. Existing unrelated virtual hosts must be preserved.
In that TLS configuration, serve HTTP/2 (`listen 443 ssl http2;` on nginx 1.24)
and keep the template's `gzip` lines; over HTTP/1.1 a browser opens several TLS
connections to load the page's assets.

After each deployment, verify anonymous HTTPS downloads and their SHA-256 digests. Keep source, runtime data, SSH keys and GitHub credentials
outside the web root. Retain the previous deployment for rollback.

Sanitized, versioned release-qualification records live in `src/acceptance/` and
are copied with the site. Keep their bytes stable: the GitHub release records
reference their public URLs and SHA-256 digests. Do not copy raw runtime logs,
databases, provider configuration or credentials into that directory.
