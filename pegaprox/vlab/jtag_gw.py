"""
MOAVI Desk - JTAG gateway VMs of the board lab (the network target).

A JTAG gateway is a small Linux VM (Vivado Lab Edition = hw_server, and Quartus jtagd / an XVC
server where used) with many JTAG cables passed through to it: per USB device, or a whole PCIe USB
controller (recommended with many cables - it survives re-enumeration such as the Platform Cable
USB II firmware load). Researchers' desktops reach its hw_server (3121) / jtagd (1309) / XVC ports
over the network and pick their cable by its serial number, so any display protocol works.

The gateway only relays programming and debug traffic; it does not build. Synthesis and
implementation run in the researcher's VM or the build farm.

This module holds the parts with no Proxmox or Flask in them: reading the cables the guest sees,
choosing free passthrough slots on the VM, and the remote power hook (an extension point; no PDU
driver ships). The routes are in pegaprox/api/vlab_next.py.
"""
import re

# USB vendors of JTAG cables: AMD Xilinx Platform Cable, FTDI (Digilent / board-integrated
# JTAG, also many UART bridges), Digilent, Intel (Altera) USB-Blaster.
JTAG_VENDORS = {'03fd': 'AMD Xilinx', '0403': 'FTDI', '1443': 'Digilent', '09fb': 'Intel (Altera)'}

# what the guest agent runs on the gateway: one line per USB device the kernel sees,
# "vid:pid|serial|manufacturer|product|port" (sysfs, no lsusb needed, no root-only -v read)
LIST_CABLES = ['/bin/sh', '-c',
               'for d in /sys/bus/usb/devices/*; do [ -f "$d/idVendor" ] || continue; '
               'printf "%s:%s|%s|%s|%s|%s\\n" "$(cat $d/idVendor)" "$(cat $d/idProduct)" '
               '"$(cat $d/serial 2>/dev/null)" "$(cat $d/manufacturer 2>/dev/null)" '
               '"$(cat $d/product 2>/dev/null)" "${d##*/}"; done']

_VIDPID = re.compile(r'^[0-9a-f]{4}:[0-9a-f]{4}$')
_PORT = re.compile(r'^\d+-[\d.]+$')          # 1-4.2 (a device; root hubs are usb1, usb2, ...)


def parse_cables(text):
    """The LIST_CABLES output -> [{vidpid, serial, manufacturer, product, port, jtag}], hubs and root
    hubs left out, JTAG vendors first. jtag = the vendor is a known JTAG cable vendor."""
    out = []
    for line in str(text or '').splitlines():
        parts = line.strip().split('|')
        if len(parts) != 5:
            continue
        vidpid, serial, manufacturer, product, port = (p.strip() for p in parts)
        vidpid = vidpid.lower()
        if not _VIDPID.match(vidpid) or not _PORT.match(port) or vidpid.startswith('1d6b:'):   # 1d6b = Linux root hub
            continue
        if 'hub' in product.lower():
            continue
        out.append({'vidpid': vidpid, 'serial': serial[:64], 'manufacturer': manufacturer[:80], 'product': product[:80],
                    'port': port, 'jtag': vidpid[:4] in JTAG_VENDORS})
    out.sort(key=lambda c: (not c['jtag'], c['port']))
    return out


# Proxmox: usb0-usb13 (machine 7.1+; older machine types stop at usb4), hostpci0-hostpci15
USB_SLOTS = tuple(f'usb{i}' for i in range(14))
PCI_SLOTS = tuple(f'hostpci{i}' for i in range(16))
_PCI = re.compile(r'^([0-9a-f]{4}:)?[0-9a-f]{2}:[0-9a-f]{2}(\.[0-7])?$')


def free_slot(raw_config, kind):
    """The first usbN / hostpciN the VM config does not use, or None."""
    used = set((raw_config or {}).keys())
    return next((s for s in (USB_SLOTS if kind == 'usb' else PCI_SLOTS) if s not in used), None)


def pci_value(path, raw_config):
    """hostpciN value for a whole USB controller: pcie=1 on a q35 machine."""
    q35 = 'q35' in str((raw_config or {}).get('machine') or '')
    return f'{path},pcie=1' if q35 else path


def valid_pci(path):
    return bool(_PCI.match(str(path or '').lower()))


# --- remote power (extension point) ------------------------------------------------------
#
# A board's `power` holds a small JSON config, e.g. {"driver": "pdu-x", "outlet": 7}. A site adds a
# driver by registering a callable here (from a plugin or a local module imported at start):
#
#     from pegaprox.vlab import jtag_gw
#     def my_pdu(board, action, cfg): ...   # action 'on' | 'off' | 'cycle'; raise on failure
#     jtag_gw.register_power_driver('pdu-x', my_pdu)
#
# Nothing ships: POST /api/vlab/admin/boards/<id>/power answers 501 until a driver is registered.

POWER_ACTIONS = ('on', 'off', 'cycle')
POWER_DRIVERS = {}


def register_power_driver(name, fn):
    POWER_DRIVERS[str(name)] = fn


def power(board, action, cfg):
    """Run the board's power driver. (True, '') or (False, why); why 'NO_DRIVER' when none fits."""
    fn = POWER_DRIVERS.get(str((cfg or {}).get('driver') or ''))
    if not fn:
        return False, 'NO_DRIVER'
    try:
        fn(board, action, cfg)
    except Exception as e:      # the driver's own error, said back to the admin
        return False, str(e)[:200] or e.__class__.__name__
    return True, ''
