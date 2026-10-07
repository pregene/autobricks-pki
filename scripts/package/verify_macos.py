#!/usr/bin/env python3
"""Inspect macOS client archives without executing target-platform binaries."""
import plistlib
import struct
import sys
import tarfile
from pathlib import Path


def verify(path, architecture, version):
    with tarfile.open(path, 'r:gz') as archive:
        prefix = path.name.removesuffix('.tar.gz')
        members = {member.name: member for member in archive.getmembers()}
        for member in members.values():
            if not (member.name == prefix or member.name.startswith(prefix + '/')):
                raise ValueError('unexpected archive root')
            if '..' in Path(member.name).parts or member.issym() or member.islnk():
                raise ValueError('unsafe archive member')
        def read(name):
            stream = archive.extractfile(prefix + '/' + name)
            if stream is None:
                raise ValueError('missing archive file: ' + name)
            return stream.read()
        if read('VERSION').decode().strip() != version or read('ARCH').decode().strip() != architecture:
            raise ValueError('package version or architecture mismatch')
        for name in ('abpki-cli', 'install.sh', 'uninstall.sh'):
            if members[prefix + '/' + name].mode & 0o111 != 0o111:
                raise ValueError('file is not executable: ' + name)
        if any(Path(name).name == 'abpkid' for name in members):
            raise ValueError('server executable in client package')
        for name in ('LICENSE', 'README.md', 'install.sh', 'uninstall.sh'):
            if not read(name):
                raise ValueError('empty package file: ' + name)
        if not any('/licenses/rust/security-framework-' in name for name in members):
            raise ValueError('missing macOS dependency legal notices')
        service = plistlib.loads(read('com.autobricks.pki.client.plist'))
        if service['Label'] != 'com.autobricks.pki.client' or not service['RunAtLoad'] or not service['KeepAlive']:
            raise ValueError('invalid launchd service')
        if service['GroupName'] != 'staff' or service['ProgramArguments'] != [
            '/usr/local/bin/abpki-cli', 'daemon', '--config',
            '/Library/Application Support/Autobricks PKI/client.json',
        ]:
            raise ValueError('invalid launchd execution or socket group')
        binary = read('abpki-cli')
        header = struct.unpack_from('<8I', binary)
        cpu = {'arm64': 0x0100000c, 'x86_64': 0x01000007}[architecture]
        if header[0] != 0xfeedfacf or header[1] != cpu or header[3] != 2:
            raise ValueError('incorrect Mach-O executable architecture')
        offset = 32
        minimum = None
        libraries = []
        entry = False
        for _ in range(header[4]):
            command, size = struct.unpack_from('<II', binary, offset)
            if size < 8 or offset + size > 32 + header[5]:
                raise ValueError('invalid Mach-O load command')
            if command == 0x32:
                platform, minimum = struct.unpack_from('<II', binary, offset + 8)
                if platform != 1:
                    raise ValueError('binary does not target macOS')
            if command == 0x24:
                minimum = struct.unpack_from('<I', binary, offset + 8)[0]
            if command in (0xc, 0x80000018, 0x8000001f):
                start = offset + struct.unpack_from('<I', binary, offset + 8)[0]
                library = binary[start:offset + size].split(b'\0', 1)[0].decode()
                if not library.startswith(('/usr/lib/', '/System/Library/Frameworks/')):
                    raise ValueError('non-system library dependency: ' + library)
                libraries.append(library)
            entry |= command == 0x80000028
            offset += size
        if minimum != 11 << 16 or not entry or not libraries:
            raise ValueError('missing entry point or unexpected macOS minimum version')
        if version.encode() not in binary:
            raise ValueError('version is not embedded in binary')
        print(f'{path.name}: Mach-O {architecture}, macOS 11.0, version {version}, archive and launchd layout OK')
        print('  System libraries: ' + ', '.join(libraries))


if __name__ == '__main__':
    build = Path(sys.argv[1])
    version = Path('VERSION').read_text().strip()
    for architecture in ('arm64', 'x86_64'):
        verify(build / f'autobricks-pki-cli-{version}-macos-{architecture}.tar.gz', architecture, version)
