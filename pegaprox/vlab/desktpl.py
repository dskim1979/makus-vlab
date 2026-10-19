# -*- coding: utf-8 -*-
"""
MOAVI Desk desktop templates (가상머신 > 이미지 > 데스크톱 템플릿): ready-made desktops for the pools of a
site - built on the cluster from a public cloud image (Linux) or the admin's Windows ISO, then
registered as a golden image (Linux, with its environment card) or a Proxmox template (Windows,
generalised with sysprep).

  office-win11   일반 업무 · Windows 11  the admin's Windows 11 ISO + virtio-win ISO, unattended setup,
                                         guest tools, RDP, Korean locale, Chrome · 7-Zip, sysprep
  research       연구원 · Ubuntu 24.04    Xfce desktop + xrdp, Korean input, dev tools, Python,
                                         JupyterLab + code-server (the portal's 웹 IDE), NFS / autofs
  gpu            GPU · AI · Ubuntu 24.04  research + NVIDIA driver (open kernel modules), CUDA, PyTorch
  npu            NPU · Ubuntu 22.04       research + the vendor SDK (FuriosaAI, Rebellions ...) from
                                         an offline package folder the admin keeps on NFS
  fpga           FPGA · Ubuntu 22.04      research + Vivado / Vitis prerequisites, JTAG cable udev
                                         rules (Xilinx, Digilent, FTDI), Vivado from the admin's
                                         installer folder on NFS (batch install, EULA accepted by the admin)

Linux builds follow pegaprox/api/templates_lib.py (download -> import -> cloud-init) and add a
cloud-init user-data snippet (cicustom) that runs /usr/local/sbin/moavi-template-build.sh on the
first boot; the engine follows its stage file through the guest agent. Nothing here stores a user
password: the Linux templates have no password login (users come from the directory), the Windows
template's local administrator gets a random password shown to the admin once.

This module is pure (texts and checks); the build itself is pegaprox/api/vlab_desktpl.py.
"""

import re
import secrets
import shlex
import string
from xml.sax.saxutils import escape as xml_escape

STAGE_FILE = '/var/lib/moavi/template-stage'
READY_FILE = '/var/lib/moavi/template-ready'
FAILED_FILE = '/var/lib/moavi/template-failed'
LOG_FILE = '/var/log/moavi-template-build.log'
WIN_DIR = r'C:\moavi'
WIN_READY = r'C:\moavi\ready.txt'
WIN_FAILED = r'C:\moavi\failed.txt'
WIN_STAGE = r'C:\moavi\stage.txt'

CODE_SERVER_VERSION = '4.96.4'
CUDA_REPOS = {'24.04': 'ubuntu2404', '22.04': 'ubuntu2204'}
CUDA_TOOLKIT = 'cuda-toolkit-12-8'
TORCH_INDEX = 'https://download.pytorch.org/whl/cu128'

# JTAG cables of FPGA boards (USB vendor ids): Xilinx Platform Cable, FTDI (most dev boards), Digilent
JTAG_VENDORS = (('03fd', 'Xilinx'), ('0403', 'FTDI'), ('1443', 'Digilent'))

PRESETS = {
    'office-win11': {
        'name': '일반 업무 · Windows 11', 'name_en': 'Office · Windows 11', 'os': 'windows', 'kind': 'general',
        'cores': 4, 'memory_mb': 8192, 'disk_gb': 80, 'output': 'template',
        'summary': 'Windows 11 무인 설치 · 게스트 도구 · RDP · 한국어 · Chrome · 7-Zip · sysprep',
        'needs': ['windows_iso', 'virtio_iso'],
    },
    'research': {
        'name': '연구원 · Ubuntu 24.04', 'name_en': 'Research · Ubuntu 24.04', 'os': 'linux', 'base': 'ubuntu-2404',
        'release': '24.04', 'kind': 'general', 'cores': 4, 'memory_mb': 8192, 'disk_gb': 64, 'output': 'golden',
        'summary': 'Xfce 데스크톱 · xrdp · 한글 입력 · 개발 도구 · Python · JupyterLab · code-server',
        'features': ['desktop', 'dev', 'ide'],
    },
    'gpu': {
        'name': 'GPU · AI · Ubuntu 24.04', 'name_en': 'GPU · AI · Ubuntu 24.04', 'os': 'linux', 'base': 'ubuntu-2404',
        'release': '24.04', 'kind': 'ai', 'cores': 8, 'memory_mb': 16384, 'disk_gb': 120, 'output': 'golden',
        'summary': '연구원 템플릿 + NVIDIA 드라이버(open) · CUDA 12.8 · PyTorch',
        'features': ['desktop', 'dev', 'ide', 'nvidia'],
    },
    'npu': {
        'name': 'NPU · Ubuntu 22.04', 'name_en': 'NPU · Ubuntu 22.04', 'os': 'linux', 'base': 'ubuntu-2204',
        'release': '22.04', 'kind': 'npu', 'cores': 8, 'memory_mb': 16384, 'disk_gb': 100, 'output': 'golden',
        'summary': '연구원 템플릿 + NPU SDK(FuriosaAI · Rebellions 등, 관리자 패키지 폴더에서)',
        'features': ['desktop', 'dev', 'ide', 'npu'],
        'optional': ['vendor_dir'],
    },
    'fpga': {
        'name': 'FPGA · Ubuntu 22.04', 'name_en': 'FPGA · Ubuntu 22.04', 'os': 'linux', 'base': 'ubuntu-2204',
        'release': '22.04', 'kind': 'fpga', 'cores': 8, 'memory_mb': 16384, 'disk_gb': 250, 'output': 'golden',
        'summary': '연구원 템플릿 + Vivado/Vitis 필수 라이브러리 · JTAG udev · Vivado(설치 파일이 있으면 자동)',
        'features': ['desktop', 'dev', 'ide', 'fpga'],
        'optional': ['vendor_dir'],
    },
}

_NFS_RE = re.compile(r'^[A-Za-z0-9.\-]{1,253}:/[A-Za-z0-9._/\-]{1,300}$')
_NAME_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$')
_VOLID_RE = re.compile(r'^[A-Za-z0-9._-]+:iso/[A-Za-z0-9._+-]+\.iso$')
_AGREE_RE = re.compile(r'^[A-Za-z0-9_,]{1,120}$')


def preset_list():
    return [dict({k: v for k, v in p.items()}, id=k) for k, p in PRESETS.items()]


def validate(preset_id, data):
    """(options, None) or (None, error text) for a build request (node / storage / bridge are checked
    against the cluster by the caller)."""
    p = PRESETS.get(preset_id)
    if not p:
        return None, 'Unknown template'
    out = {'preset': preset_id}
    name = str(data.get('name') or '').strip() or f'moavi-{preset_id}'
    if not _NAME_RE.fullmatch(name):
        return None, 'name: letters, digits, "-" and ".", up to 63'
    out['name'] = name
    for k, lo, hi in (('cores', 1, 128), ('memory_mb', 1024, 1048576), ('disk_gb', 16, 65536)):
        v = data.get(k, p[k])
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            return None, f'{k} must be a whole number from {lo} to {hi}'
        out[k] = v
    if p['os'] == 'windows':
        for k in ('windows_iso', 'virtio_iso'):
            v = str(data.get(k) or '')
            if not _VOLID_RE.fullmatch(v):
                return None, f'{k}: an ISO of a storage (storage:iso/name.iso)'
            out[k] = v
        edition = str(data.get('edition') or 'Windows 11 Pro').strip()
        if not re.fullmatch(r'Windows 1[01] [A-Za-z ]{2,40}', edition):
            return None, 'edition: the image name in the ISO, e.g. "Windows 11 Pro"'
        out['edition'] = edition
        lang = str(data.get('language') or 'ko-KR')
        if lang not in ('ko-KR', 'en-US'):
            return None, 'language: ko-KR or en-US (the language of the ISO)'
        out['language'] = lang
    vendor = str(data.get('vendor_dir') or '').strip()
    if vendor:
        if 'vendor_dir' not in p.get('optional', ()):
            return None, 'vendor_dir is for the NPU and FPGA templates'
        if not _NFS_RE.fullmatch(vendor):
            return None, 'vendor_dir: an NFS export, server:/path'
        out['vendor_dir'] = vendor
    if preset_id == 'fpga' and vendor:
        if data.get('accept_eula') is not True:
            return None, 'Installing Vivado accepts the AMD license agreements: tick accept_eula'
        agree = str(data.get('agree') or 'XilinxEULA,3rdPartyEULA')
        if not _AGREE_RE.fullmatch(agree):
            return None, 'agree: the xsetup --agree terms, comma separated'
        out['agree'] = agree
        out['accept_eula'] = True
    return out, None


# --- Linux: cloud-init user-data and the first-boot build script -----------------------------

def _yaml_str(s):
    """A YAML double-quoted scalar."""
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"') + '"'


def _block(text, indent=6):
    pad = ' ' * indent
    return '\n'.join(pad + line if line else '' for line in text.split('\n'))


def udev_rules():
    lines = ['# MOAVI Desk: FPGA JTAG cables for every user of the desktop (Vivado hw_server, openFPGALoader)']
    for vid, label in JTAG_VENDORS:
        lines.append(f'# {label}')
        lines.append(f'SUBSYSTEM=="usb", ATTR{{idVendor}}=="{vid}", MODE="0666"')
    return '\n'.join(lines) + '\n'


def build_script(opts):
    """bash run once by cloud-init (runcmd) as root. Writes its stage to STAGE_FILE, READY_FILE at the
    end, FAILED_FILE with the failing step on an error."""
    p = PRESETS[opts['preset']]
    feats = p.get('features', [])
    q = shlex.quote
    rel = p['release']
    s = [
        '#!/bin/bash',
        '# MOAVI Desk desktop template build (pegaprox/vlab/desktpl.py) - runs once on the first boot',
        'set -o pipefail',
        f'exec >>{LOG_FILE} 2>&1',
        'export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a',
        'mkdir -p /var/lib/moavi',
        f'stage() {{ echo "$1" > {STAGE_FILE}; echo "== $(date -Is) $1"; }}',
        f'fail() {{ echo "$1" > {FAILED_FILE}; echo "!! $(date -Is) failed: $1"; exit 1; }}',
        'apt_get() { for i in 1 2 3; do apt-get -y -o Dpkg::Options::=--force-confold "$@" && return 0; sleep 20; apt-get update; done; return 1; }',
        'stage update',
        'apt-get update || fail "apt update"',
        'apt_get dist-upgrade || fail "upgrade"',
        'apt_get install qemu-guest-agent spice-vdagent curl wget ca-certificates gnupg locales || fail "base packages"',
        'systemctl enable --now qemu-guest-agent',
        'locale-gen ko_KR.UTF-8 en_US.UTF-8; update-locale LANG=ko_KR.UTF-8',
        'timedatectl set-timezone Asia/Seoul || ln -sf /usr/share/zoneinfo/Asia/Seoul /etc/localtime',
    ]
    if 'desktop' in feats:
        s += [
            'stage desktop',
            'apt_get install --no-install-recommends xfce4 xfce4-goodies xfce4-terminal lightdm lightdm-gtk-greeter '
            'dbus-x11 xorg xrdp xorgxrdp network-manager-gnome || fail "desktop"',
            'apt_get install language-pack-ko fonts-nanum fonts-noto-cjk fcitx5 fcitx5-hangul fcitx5-config-qt im-config || fail "korean input"',
            'apt_get install firefox || true',
            # every user's RDP / console session is Xfce with Hangul input
            "echo 'xfce4-session' > /etc/skel/.xsession",
            "printf 'export GTK_IM_MODULE=fcitx\\nexport QT_IM_MODULE=fcitx\\nexport XMODIFIERS=@im=fcitx\\n' > /etc/profile.d/moavi-ime.sh",
            "printf '[Desktop Entry]\\nType=Application\\nName=fcitx5\\nExec=fcitx5 -d\\n' > /etc/xdg/autostart/moavi-fcitx5.desktop",
            # xrdp: no "authentication required to create a color managed device" prompt in RDP sessions
            "mkdir -p /etc/polkit-1/localauthority/50-local.d",
            "printf '[Allow colord]\\nIdentity=unix-user:*\\nAction=org.freedesktop.color-manager.*\\nResultAny=no\\nResultInactive=no\\nResultActive=yes\\n'"
            " > /etc/polkit-1/localauthority/50-local.d/45-moavi-colord.pkla",
            'adduser xrdp ssl-cert 2>/dev/null || true',
            'systemctl enable xrdp lightdm',
            # ready for 내장 디렉터리 자동 조인 (realm join through the guest agent)
            'apt_get install realmd sssd sssd-tools adcli krb5-user samba-common-bin oddjob oddjob-mkhomedir packagekit || fail "directory join tools"',
            "grep -q pam_mkhomedir /etc/pam.d/common-session || echo 'session optional pam_mkhomedir.so skel=/etc/skel umask=077' >> /etc/pam.d/common-session",
        ]
    if 'dev' in feats:
        s += [
            'stage dev',
            'apt_get install build-essential git git-lfs cmake pkg-config vim nano htop tmux unzip zip rsync '
            'python3 python3-venv python3-pip python3-dev nfs-common autofs || fail "dev tools"',
        ]
    if 'ide' in feats:
        s += [
            'stage ide',
            'python3 -m venv /opt/jupyter || fail "jupyter venv"',
            '/opt/jupyter/bin/pip install --upgrade pip wheel || fail "pip"',
            '/opt/jupyter/bin/pip install jupyterlab jupyter-server-proxy jupyter-vscode-proxy ipykernel ipywidgets '
            'numpy pandas matplotlib scipy || fail "jupyterlab"',
            'ln -sf /opt/jupyter/bin/jupyter /usr/local/bin/jupyter',
            f'curl -fsSL -o /tmp/code-server.deb https://github.com/coder/code-server/releases/download/v{CODE_SERVER_VERSION}/code-server_{CODE_SERVER_VERSION}_amd64.deb'
            ' || fail "code-server download"',
            'apt_get install /tmp/code-server.deb || fail "code-server"',
            'rm -f /tmp/code-server.deb',
        ]
    if 'nvidia' in feats:
        repo = CUDA_REPOS[rel]
        s += [
            'stage nvidia',
            f'curl -fsSL -o /tmp/cuda-keyring.deb https://developer.download.nvidia.com/compute/cuda/repos/{repo}/x86_64/cuda-keyring_1.1-1_all.deb || fail "cuda keyring"',
            'dpkg -i /tmp/cuda-keyring.deb && rm -f /tmp/cuda-keyring.deb && apt-get update || fail "cuda repo"',
            # the open kernel modules (Turing and later, every datacenter card a pool passes through)
            f'apt_get install nvidia-open {CUDA_TOOLKIT} || fail "nvidia driver and CUDA"',
            "printf 'export PATH=/usr/local/cuda/bin:$PATH\\nexport LD_LIBRARY_PATH=/usr/local/cuda/lib64:${LD_LIBRARY_PATH}\\n' > /etc/profile.d/moavi-cuda.sh",
            'stage pytorch',
            f'/opt/jupyter/bin/pip install torch torchvision torchaudio --index-url {TORCH_INDEX} || fail "pytorch"',
        ]
    if 'npu' in feats or 'fpga' in feats:
        vendor = opts.get('vendor_dir', '')
        s += ['stage vendor-mount', 'mkdir -p /mnt/moavi-vendor']
        if vendor:
            s += [f'mount -t nfs -o ro,nolock {q(vendor)} /mnt/moavi-vendor || fail "mount {vendor}"']
    if 'npu' in feats:
        s += [
            'stage npu',
            # the vendor's own packages, as the admin downloaded them (driver, runtime, SDK): every .deb, then every .whl
            'if ls /mnt/moavi-vendor/*.deb >/dev/null 2>&1; then apt_get install /mnt/moavi-vendor/*.deb || fail "npu packages"; fi',
            'if ls /mnt/moavi-vendor/*.whl >/dev/null 2>&1; then /opt/jupyter/bin/pip install /mnt/moavi-vendor/*.whl || fail "npu python packages"; fi',
            'if [ -x /mnt/moavi-vendor/install.sh ]; then (cd /mnt/moavi-vendor && ./install.sh) || fail "npu install.sh"; fi',
        ]
    if 'fpga' in feats:
        s += [
            'stage fpga',
            'apt_get install libtinfo5 libncurses5 libncursesw5 libx11-6 libxext6 libxrender1 libxtst6 libxi6 libfreetype6 '
            'fontconfig libgtk2.0-0 libcanberra-gtk-module libcanberra-gtk3-module xvfb gcc g++ make libusb-1.0-0 '
            '|| fail "fpga libraries"',
            f"cat > /etc/udev/rules.d/52-moavi-jtag.rules <<'EOF'\n{udev_rules()}EOF",
            'udevadm control --reload-rules || true',
        ]
        if opts.get('vendor_dir'):
            agree = opts.get('agree', 'XilinxEULA,3rdPartyEULA')
            s += [
                'stage vivado',
                'xs=$(find /mnt/moavi-vendor -maxdepth 3 -name xsetup -type f | head -1)',
                '[ -n "$xs" ] || fail "no xsetup in the installer folder"',
                'cfg=$(dirname "$xs")/install_config.txt; [ -f "$cfg" ] || cfg=/mnt/moavi-vendor/install_config.txt',
                '[ -f "$cfg" ] || fail "no install_config.txt (make it once with: xsetup -b ConfigGen)"',
                # the admin ticked "I accept the AMD license agreements" in the console (accept_eula)
                f'"$xs" --agree {q(agree)} --batch Install --config "$cfg" || fail "vivado install"',
                'drv=$(find /tools /opt -path "*cable_drivers/lin64/install_script/install_drivers/install_drivers" -type f 2>/dev/null | head -1)',
                '[ -n "$drv" ] && (cd "$(dirname "$drv")" && ./install_drivers) || true',
                's64=$(find /tools /opt -maxdepth 5 -name settings64.sh -path "*Vivado*" 2>/dev/null | head -1)',
                '[ -n "$s64" ] && echo "source $s64" > /etc/profile.d/moavi-vivado.sh',
            ]
    if 'npu' in feats or 'fpga' in feats:
        s += ['umount /mnt/moavi-vendor 2>/dev/null || true']
    s += [
        'stage cleanup',
        'apt-get -y autoremove; apt-get clean',
        # no login of its own: the cloud image's default user is locked (people sign in with their directory account)
        "for u in ubuntu debian; do id \"$u\" >/dev/null 2>&1 && passwd -l \"$u\"; done",
        'stage done',
        f'date -Is > {READY_FILE}',
    ]
    return '\n'.join(s) + '\n'


def user_data(opts):
    """#cloud-config for the build VM (Proxmox cicustom user=)."""
    script = build_script(opts)
    return '\n'.join([
        '#cloud-config',
        '# MOAVI Desk desktop template build (pegaprox/vlab/desktpl.py)',
        f'hostname: {opts["name"]}',
        'ssh_pwauth: false',
        'disable_root: true',
        'package_update: false',
        'write_files:',
        '  - path: /usr/local/sbin/moavi-template-build.sh',
        "    permissions: '0700'",
        '    content: |',
        _block(script, 6),
        'runcmd:',
        '  - [bash, /usr/local/sbin/moavi-template-build.sh]',
        '',
    ])


# the guest agent reads where the build is: "stage <name>", "ready", "failed <step>"
STATUS_LINUX = (f'if [ -f {READY_FILE} ]; then echo ready; elif [ -f {FAILED_FILE} ]; then echo "failed $(cat {FAILED_FILE})"; '
                f'else echo "stage $(cat {STAGE_FILE} 2>/dev/null || echo boot)"; fi; tail -n 3 {LOG_FILE} 2>/dev/null')

# before the VM becomes a golden image: what makes each clone its own (cloud-init, machine id, host keys)
SEAL_LINUX = ('cloud-init clean --logs --seed 2>/dev/null; rm -f /var/lib/moavi/template-*; '
              'truncate -s 0 /etc/machine-id; rm -f /var/lib/dbus/machine-id; ln -sf /etc/machine-id /var/lib/dbus/machine-id; '
              'rm -f /etc/ssh/ssh_host_*; fstrim -av >/dev/null 2>&1; sync; echo sealed')

LINUX_STAGES = ('boot', 'update', 'desktop', 'dev', 'ide', 'nvidia', 'pytorch', 'vendor-mount', 'npu', 'fpga', 'vivado', 'cleanup', 'done')


def stage_progress(preset_id, stage):
    """30..90 for the stage the guest is in (the steps before and after the guest are the rest)."""
    p = PRESETS[preset_id]
    feats = set(p.get('features', []))
    names = ['boot', 'update']
    names += [n for n, f in (('desktop', 'desktop'), ('dev', 'dev'), ('ide', 'ide'), ('nvidia', 'nvidia'),
                             ('pytorch', 'nvidia'), ('vendor-mount', None), ('npu', 'npu'), ('fpga', 'fpga'),
                             ('vivado', 'fpga')) if f in feats or (f is None and feats & {'npu', 'fpga'})]
    names += ['cleanup', 'done']
    i = names.index(stage) if stage in names else 0
    return 30 + int(60 * i / max(1, len(names) - 1))


# --- Windows 11: unattended setup ----------------------------------------------------------------

def random_password(n=18):
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = ''.join(secrets.choice(alphabet) for _ in range(n - 2)) + secrets.choice('!#%*+-=?@') + secrets.choice(string.digits)
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
            return pw


WIN_ADMIN = 'moavi-admin'
_DRIVE_LETTERS = 'DEFGH'
# the driver folders of the virtio-win ISO that setup needs: storage (vioscsi), network (NetKVM), memory balloon
_VIRTIO_DIRS = ('vioscsi', 'NetKVM', 'Balloon', 'viostor')


def _component(name, pass_, body):
    return (f'    <component name="{name}" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" '
            f'versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" '
            f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n{body}\n    </component>')


def autounattend(opts, admin_password):
    """autounattend.xml on its own CD: disk, edition, virtio drivers, Korean locale, RDP on, one local
    administrator (logged on once to run C:\\moavi\\firstlogon.ps1), no online account screens."""
    lang = opts['language']
    ilocale = '0412:00000412' if lang == 'ko-KR' else '0409:00000409'
    pw = xml_escape(admin_password)
    drivers = '\n'.join(
        f'        <PathAndCredentials wcm:action="add" wcm:keyValue="{i}"><Path>{d}:\\{folder}\\w11\\amd64</Path></PathAndCredentials>'
        for i, (d, folder) in enumerate(((d, f) for f in _VIRTIO_DIRS for d in _DRIVE_LETTERS), start=1))
    pe_intl = _component('Microsoft-Windows-International-Core-WinPE', 'windowsPE', f'''      <SetupUILanguage><UILanguage>{lang}</UILanguage></SetupUILanguage>
      <InputLocale>{ilocale}</InputLocale><SystemLocale>{lang}</SystemLocale><UILanguage>{lang}</UILanguage><UserLocale>{lang}</UserLocale>''')
    pe_drivers = _component('Microsoft-Windows-PnpCustomizationsWinPE', 'windowsPE', f'      <DriverPaths>\n{drivers}\n      </DriverPaths>')
    pe_setup = _component('Microsoft-Windows-Setup', 'windowsPE', f'''      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall><OSImage>
        <InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/NAME</Key><Value>{xml_escape(opts['edition'])}</Value></MetaData></InstallFrom>
        <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
      </OSImage></ImageInstall>
      <UserData><AcceptEula>true</AcceptEula><FullName>MOAVI Desk</FullName><Organization>MOAVI Desk</Organization></UserData>''')
    spec_shell = _component('Microsoft-Windows-Shell-Setup', 'specialize',
                            '      <ComputerName>*</ComputerName><TimeZone>Korea Standard Time</TimeZone>')
    spec_ts = _component('Microsoft-Windows-TerminalServices-LocalSessionManager', 'specialize', '      <fDenyTSConnections>false</fDenyTSConnections>')
    spec_fw = _component('Microsoft-Windows-Networking-MPSSVC-Svc', 'specialize',
                         '      <FirewallGroups><FirewallGroup wcm:action="add" wcm:keyValue="rdp"><Active>true</Active>'
                         '<Group>@FirewallAPI.dll,-28752</Group><Profile>all</Profile></FirewallGroup></FirewallGroups>')
    # no device encryption (sysprep refuses an encrypting disk) and no store updates racing sysprep
    spec_run = _component('Microsoft-Windows-Deployment', 'specialize', '''      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\BitLocker /v PreventDeviceEncryption /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>2</Order><Path>reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsStore /v AutoDownload /t REG_DWORD /d 2 /f</Path></RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>3</Order><Path>reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
      </RunSynchronous>''')
    oobe_intl = _component('Microsoft-Windows-International-Core', 'oobeSystem',
                           f'      <InputLocale>{ilocale}</InputLocale><SystemLocale>{lang}</SystemLocale><UILanguage>{lang}</UILanguage><UserLocale>{lang}</UserLocale>')
    first = (f'cmd /c for %d in ({" ".join(_DRIVE_LETTERS)}) do if exist %d:\\moavi\\firstlogon.ps1 '
             f'(mkdir {WIN_DIR} &amp; copy /y %d:\\moavi\\*.* {WIN_DIR}\\ &amp; powershell -NoProfile -ExecutionPolicy Bypass -File {WIN_DIR}\\firstlogon.ps1)')
    oobe_shell = _component('Microsoft-Windows-Shell-Setup', 'oobeSystem', f'''      <OOBE>
        <HideEULAPage>true</HideEULAPage><HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <HideLocalAccountScreen>true</HideLocalAccountScreen><ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts><LocalAccounts><LocalAccount wcm:action="add">
        <Name>{WIN_ADMIN}</Name><Group>Administrators</Group><DisplayName>MOAVI admin</DisplayName>
        <Password><Value>{pw}</Value><PlainText>true</PlainText></Password>
      </LocalAccount></LocalAccounts></UserAccounts>
      <AutoLogon><Enabled>true</Enabled><Username>{WIN_ADMIN}</Username><LogonCount>1</LogonCount>
        <Password><Value>{pw}</Value><PlainText>true</PlainText></Password></AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add"><Order>1</Order><CommandLine>{first}</CommandLine><Description>MOAVI Desk template</Description></SynchronousCommand>
      </FirstLogonCommands>''')
    return ('<?xml version="1.0" encoding="utf-8"?>\n<unattend xmlns="urn:schemas-microsoft-com:unattend">\n'
            f'  <settings pass="windowsPE">\n{pe_intl}\n{pe_drivers}\n{pe_setup}\n  </settings>\n'
            f'  <settings pass="specialize">\n{spec_shell}\n{spec_ts}\n{spec_fw}\n{spec_run}\n  </settings>\n'
            f'  <settings pass="oobeSystem">\n{oobe_intl}\n{oobe_shell}\n  </settings>\n</unattend>\n')


# apps every office desktop gets (direct MSI links of the vendors - winget is not ready on a fresh install)
WIN_APPS = (
    ('Google Chrome', 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'),
    ('7-Zip', 'https://www.7-zip.org/a/7z2409-x64.msi'),
)


def firstlogon_ps1():
    """Runs at the first logon of the setup account: virtio guest tools (drivers, QEMU guest agent, SPICE),
    power settings, the office apps; writes C:\\moavi\\ready.txt (or failed.txt). sysprep is the engine's
    next step through the guest agent."""
    apps = '\n'.join(f"  @{{n='{n}'; u='{u}'}}," for n, u in WIN_APPS).rstrip(',')
    return f'''$ErrorActionPreference = 'Stop'
$log = '{WIN_DIR}\\build.log'
function Stage($s) {{ Set-Content -Path '{WIN_STAGE}' -Value $s; Add-Content -Path $log -Value "== $(Get-Date -Format s) $s" }}
try {{
  Stage 'guest-tools'
  $gt = Get-PSDrive -PSProvider FileSystem | ForEach-Object {{ Join-Path $_.Root 'virtio-win-guest-tools.exe' }} | Where-Object {{ Test-Path $_ }} | Select-Object -First 1
  if (-not $gt) {{ throw 'virtio-win-guest-tools.exe not found on any CD' }}
  Start-Process -FilePath $gt -ArgumentList '/install','/passive','/norestart' -Wait
  Stage 'settings'
  powercfg /change standby-timeout-ac 0; powercfg /change monitor-timeout-ac 0; powercfg /hibernate off
  Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0
  Enable-NetFirewallRule -DisplayGroup '@FirewallAPI.dll,-28752' -ErrorAction SilentlyContinue
  Stage 'apps'
  $apps = @(
{apps}
  )
  foreach ($a in $apps) {{
    $f = Join-Path $env:TEMP ([IO.Path]::GetFileName($a.u))
    try {{ Invoke-WebRequest -UseBasicParsing -Uri $a.u -OutFile $f; Start-Process msiexec.exe -ArgumentList '/i', $f, '/qn', '/norestart' -Wait
           Add-Content -Path $log -Value "installed $($a.n)" }}
    catch {{ Add-Content -Path $log -Value "skipped $($a.n): $($_.Exception.Message)" }}
  }}
  Stage 'ready'
  Set-Content -Path '{WIN_READY}' -Value (Get-Date -Format s)
}} catch {{
  Set-Content -Path '{WIN_FAILED}' -Value $_.Exception.Message
}}
'''


def oobe_xml(language='ko-KR'):
    """The answer file sysprep /oobe uses for every clone: no OOBE screens, Korean locale; accounts come
    from the directory (or the moavi-admin kept in the template)."""
    ilocale = '0412:00000412' if language == 'ko-KR' else '0409:00000409'
    intl = _component('Microsoft-Windows-International-Core', 'oobeSystem',
                      f'      <InputLocale>{ilocale}</InputLocale><SystemLocale>{language}</SystemLocale><UILanguage>{language}</UILanguage><UserLocale>{language}</UserLocale>')
    shell = _component('Microsoft-Windows-Shell-Setup', 'oobeSystem', '''      <OOBE>
        <HideEULAPage>true</HideEULAPage><HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <HideLocalAccountScreen>true</HideLocalAccountScreen><ProtectYourPC>3</ProtectYourPC>
      </OOBE><TimeZone>Korea Standard Time</TimeZone>''')
    spec = _component('Microsoft-Windows-Shell-Setup', 'specialize', '      <ComputerName>*</ComputerName>')
    return ('<?xml version="1.0" encoding="utf-8"?>\n<unattend xmlns="urn:schemas-microsoft-com:unattend">\n'
            f'  <settings pass="specialize">\n{spec}\n  </settings>\n'
            f'  <settings pass="oobeSystem">\n{intl}\n{shell}\n  </settings>\n</unattend>\n')


STATUS_WINDOWS = (f"if (Test-Path '{WIN_READY}') {{ 'ready' }} elseif (Test-Path '{WIN_FAILED}') {{ 'failed ' + (Get-Content '{WIN_FAILED}' -Raw) }} "
                  f"else {{ 'stage ' + ((Get-Content '{WIN_STAGE}' -ErrorAction SilentlyContinue) -join '') }}")

# provisioned-only apps (sysprep fails on an app installed for the setup user only), then generalise and shut down
SYSPREP_WINDOWS = (
    "Get-AppxPackage -AllUsers | Where-Object { $_.NonRemovable -eq $false -and -not (Get-AppxProvisionedPackage -Online | "
    "Where-Object DisplayName -eq $_.Name) } | ForEach-Object { try { Remove-AppxPackage -Package $_.PackageFullName -AllUsers } catch {} }; "
    # the setup password must not stay behind: Windows' own copies of the answer file, the auto logon
    f"Remove-Item '{WIN_DIR}\\firstlogon.ps1','{WIN_DIR}\\autounattend.xml',\"$env:SystemRoot\\Panther\\unattend*.xml\","
    f"\"$env:SystemRoot\\Panther\\Unattend\\*.xml\" -ErrorAction SilentlyContinue; "
    "$wl = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'; "
    "Remove-ItemProperty -Path $wl -Name DefaultPassword -ErrorAction SilentlyContinue; Set-ItemProperty -Path $wl -Name AutoAdminLogon -Value 0; "
    f"Start-Process -FilePath \"$env:SystemRoot\\System32\\Sysprep\\sysprep.exe\" -ArgumentList '/generalize','/oobe','/shutdown','/quiet',"
    f"'/unattend:{WIN_DIR}\\oobe.xml'; 'sysprep started'")


def parse_status(text):
    """('ready' | 'failed' | 'stage', detail) from STATUS_LINUX / STATUS_WINDOWS output."""
    first = (text or '').strip().split('\n', 1)[0].strip()
    if first == 'ready':
        return 'ready', ''
    if first.startswith('failed'):
        return 'failed', first[6:].strip()
    if first.startswith('stage'):
        return 'stage', first[5:].strip() or 'boot'
    return 'stage', 'boot'
