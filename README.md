# Parallels Desktop Activator


One-command activation bypass for Parallels Desktop 26.4.x on Apple Silicon. Patches the license gates in `prl_disp_service` + `prl_vm_app`, deploys a Pro license valid until 2099, restarts the dispatcher, and re-registers your VMs. Run once, done.

## Usage

1. Install Parallels Desktop from parallels.com, sign in, start a trial.
2. Double-click `runme.command` — or run `sudo python3 parallels_activator.py`.

That's it. Open Parallels Desktop and start your VMs.

## Flags

`--restore` put original binaries back · `--keygen` deploy license only · `--test` prove the bypass with zero license on disk · `--keep-license` leave an existing license alone

## Source

`parallels_activator.py` is the entire tool — Python 3, stdlib only, macOS arm64. Nothing to build, run it directly.

## License

MIT

---
This script is intended for personal use only. If you use Parallels for work or make money from it then consider paying what you can on the Parallels site.
