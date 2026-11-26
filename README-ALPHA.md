# Linux alpha launcher template

From r5 onward the Darwin launcher is maintained in-repo at
`bundle/launcher/gyreld-launch-darwin.sh`; staging assembles it into
`bin/gyreld-launch.sh`. The published r4 bundle launcher is otherwise unchanged.

The Linux/arm64 launcher and systemd unit are shipped as templates. They have
not yet been run on a native Linux host; live acceptance is a separate slice.
Rootless operation is unsupported in the pinned alpha because loop-device
access and containerd rootless support remain open. The supplied user unit
therefore cannot start successfully as an ordinary user; it is a packaging
template, not a claim of rootless support.

Build inputs include `scripts/build-libkrun-linux.sh`,
`scripts/build-nerdbox-linux-rootfs.sh`, and `scripts/build-nerdbox-shim.sh`.
Run `scripts/verify-libkrun-linux-prefix.sh` on the libkrun prefix before
assembly. Follow the alpha bundle assembly and verifier instructions in
[build/README.md](build/README.md#alpha-bundle-assembly); the verifier produces
`RUNTIME-ARTIFACTS.json` and checks `build/digests.yaml`. Stage the Linux
launcher as `bin/gyreld-launch.sh`. It reads those records for managed daemon
arguments. Install e2fsprogs and ensure `mkfs.ext4` is on PATH.

For a package path without spaces or sed metacharacters, substitute the absolute
launcher path in the user unit, then reload systemd:

```sh
sed 's|@LAUNCHER@|/absolute/path/to/bin/gyreld-launch.sh|g' deploy/systemd/gyrel-sandboxes.service > ~/.config/systemd/user/gyrel-sandboxes.service
systemctl --user daemon-reload
```

The unit uses shared `/tmp` for the managed socket contract. State and logs are
under `GYREL_STATE_DIR`. A rootful deployment needs an appropriately adapted
system service and native-host validation; do not treat this user template as a
working rootful installation.
