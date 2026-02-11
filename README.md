# ipmi-cdrom-share

Serve an ISO over SMB1 for IPMI/BMC virtual media. Single binary, zero config, zero dependencies.

Most BMC implementations (Supermicro, Dell iDRAC, HP iLO) only support SMB1 for virtual media mounting. Running a full Samba install to share one read-only file is overkill. This does the minimum needed.

## Quick Start

```bash
go build -o ipmi-cdrom-share .
sudo ./ipmi-cdrom-share /path/to/TrueNAS-SCALE-25.10.1.iso
```

In your BMC virtual media settings:

| Field | Value |
|-------|-------|
| Share Host | `192.168.1.x` (your server IP) |
| Share Name | `share` |
| Path to Image | `TrueNAS-SCALE-25.10.1.iso` |
| User | *(blank)* |
| Password | *(blank)* |

Or as a UNC path: `\\192.168.1.x\share\TrueNAS-SCALE-25.10.1.iso`

## Usage

```
sudo ./ipmi-cdrom-share <iso-path> [listen-addr]
```

Port 445 is the default and requires root. Alternatives:

```bash
# Custom port (if your BMC supports non-standard ports)
sudo ./ipmi-cdrom-share /path/to/file.iso :8445

# Bind to specific interface
sudo ./ipmi-cdrom-share /path/to/file.iso 192.168.1.100:445

# Use setcap instead of root
sudo setcap cap_net_bind_service=+ep ./ipmi-cdrom-share
./ipmi-cdrom-share /path/to/file.iso
```

## How It Works

Implements the bare minimum of SMB1/CIFS to satisfy BMC virtual media clients:

1. **NEGOTIATE** — Selects the "NT LM 0.12" dialect
2. **SESSION_SETUP** — Accepts any credentials as guest
3. **TREE_CONNECT** — Serves a single share called `share`
4. **NT_CREATE** — Opens the ISO file, returns its size
5. **READ** — Serves file data with 64-bit offset support (ISOs > 4GB)
6. **CLOSE / DISCONNECT / LOGOFF** — Cleans up

No NTLM, no encryption, no write support. Security is share-level with no password — exactly what BMCs expect for anonymous virtual media.

## Testing

```bash
# Verify with smbclient
smbclient //localhost/share -N -m NT1 -c 'ls'

# Mount locally
sudo mount -t cifs //localhost/share /mnt -o vers=1.0,guest,sec=none
ls -la /mnt/

# Checksum verification
md5sum /path/to/original.iso /mnt/original.iso
```

## Tested BMCs

- Supermicro X11/X12 series IPMI

## Building

Requires Go 1.22+. No external dependencies.

```bash
go build -o ipmi-cdrom-share .
```

Cross-compile for a different server:

```bash
GOOS=linux GOARCH=amd64 go build -o ipmi-cdrom-share .
```

## License

MIT
