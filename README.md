# discord-spotify-blocker

A small Go utility that disables Discord from pausing your Spotify when in a voice channel.

> ⚠️ **Must be run as Administrator.**  
> This is required so the tool can generate + install certificates and make the initial file edits.

---

## What It Does
- Blocks Discord’s Spotify / Rich Presence functionality  
- Installs a local cert (first run only)
- Automatically launches Discord with proxy
---

## Build & Run

```bash
git clone https://github.com/chambres/discord-spotify-blocker
cd discord-spotify-blocker
go build -o discord-spotify-blocker .
```
If you want no command line to show up, build with
```
go build -ldflags "-H=windowsgui" -o discord-spotify-blocker.exe
```
