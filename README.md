# Sift

AI spam filtering for iCloud Mail, running on your own hardware.

Download the Mac app at [sift.weisssolutions.org](https://sift.weisssolutions.org). The app installs the Sift server over SSH on any always-on Mac, Linux box, or Raspberry Pi, then the server watches your iCloud inbox and moves spam to Junk.

## Layout

- `server/`: Go server. IMAP watcher, classifier, abuse reports, HTTPS + SSE API (`docs/api-contract.md`).
- `macos/`: SwiftUI app. `project.yml` is the XcodeGen spec and holds the version.
- `site/`: landing page, published to the `gh-pages` branch.

## Develop

```sh
./scripts/build-server.sh            # cross-compile server binaries into the app bundle
xcodegen generate --spec macos/project.yml
open macos/Sift.xcodeproj
(cd server && go test ./...)
```

## Release

```sh
./scripts/release.sh 0.2.0
```

This bumps the version, tags `v0.2.0`, and pushes. The tag runs `.github/workflows/release.yml`, which signs and notarizes the app, attaches the DMG and server binaries to a GitHub release, and adds the build to the Sparkle appcast. Installed apps update themselves, then offer to update the server.

## License

[MIT](LICENSE)
