#!/usr/bin/env python3
"""Interactive installation screen preview; performs no installation or writes."""
import argparse
import curses
import ipaddress
from pathlib import Path
import re
import secrets
import string
import sys
import time
import threading
import queue


SERVER_FIELDS = (
    ('Base domain', 'autobricks.internal'),
    ('DNS registration IP', ''),
    ('Bind address', '0.0.0.0'),
    ('Management TLS port', '5545'),
    ('Public HTTPS port', '5546'),
)
CLIENT_FIELDS = (
    ('Server address', ''),
    ('Management TLS port', '5545'),
    ('Public HTTPS port', '5546'),
)


FIELD_LIMITS = {
    'Base domain': 24,
    'DNS registration IP': 45,
    'Bind address': 45,
    'Management TLS port': 5,
    'Public HTTPS port': 5,
    'Server address': 253,
}


def edit_value(label, value, position, key):
    position = max(0, min(position, len(value)))
    if key == curses.KEY_LEFT:
        return value, max(0, position - 1), None
    if key == curses.KEY_RIGHT:
        return value, min(len(value), position + 1), None
    if key == curses.KEY_HOME:
        return value, 0, None
    if key == curses.KEY_END:
        return value, len(value), None
    if key in (curses.KEY_BACKSPACE, '\x7f', '\b'):
        if position == 0:
            return value, position, None
        return value[:position - 1] + value[position:], position - 1, ''
    if key == curses.KEY_DC:
        return value[:position] + value[position + 1:], position, ''
    if key == '\x15':
        return '', 0, ''
    if not isinstance(key, str) or not key.isprintable():
        return value, position, None
    if not key.isascii():
        return value, position, 'Use ASCII characters only.'
    if 'port' in label:
        allowed = key.isdigit()
        message = 'Use digits only.'
    elif label in ('DNS registration IP', 'Bind address'):
        allowed = key in '0123456789abcdefABCDEF:.'
        message = 'Use an IPv4 or IPv6 address.'
    else:
        allowed = key.isalnum() or key in ('.-:' if label == 'Server address' else '.-')
        message = 'Use letters, digits, dots, and hyphens.'
    if not allowed:
        return value, position, message
    limit = FIELD_LIMITS[label]
    if len(value) >= limit:
        return value, position, f'Maximum {limit} characters.'
    return value[:position] + key + value[position:], position + 1, ''


def domain_valid(value):
    return len(value) <= 253 and all(
        re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
        for label in value.split('.'))


def address_valid(value):
    try:
        address = ipaddress.ip_address(value)
        return not address.is_unspecified and not address.is_multicast
    except ValueError:
        return False


def validate(mode, values):
    errors = {}
    if mode == 'server':
        domain = values['Base domain']
        if not domain_valid(domain) or len(domain) > 24:
            errors['Base domain'] = 'Use a DNS domain of 1-24 ASCII characters.'
        else:
            try:
                ipaddress.ip_address(domain)
                errors['Base domain'] = 'Use a domain name, not an IP address.'
            except ValueError:
                pass
        if not address_valid(values['DNS registration IP']):
            errors['DNS registration IP'] = 'Enter a reachable unicast IPv4 or IPv6 address.'
        try:
            address = ipaddress.ip_address(values['Bind address'])
            if address.is_multicast:
                raise ValueError()
        except ValueError:
            errors['Bind address'] = 'Enter a listen IP address, without a port.'
    else:
        address = values['Server address']
        if not address_valid(address):
            try:
                ipaddress.ip_address(address)
                errors['Server address'] = 'Use a reachable server address.'
            except ValueError:
                if not domain_valid(address) or re.fullmatch(r'[0-9.]+', address):
                    errors['Server address'] = 'Enter a DNS name or IP, without a URL or port.'
    for label in ('Management TLS port', 'Public HTTPS port'):
        value = values[label]
        if not value.isascii() or not value.isdigit() or not 1 <= int(value) <= 65535:
            errors[label] = 'Enter a port from 1 to 65535.'
    if not any('port' in key for key in errors):
        if int(values['Management TLS port']) == int(values['Public HTTPS port']):
            errors['Public HTTPS port'] = 'The two ports must differ.'
    return errors


class Preview:
    def __init__(self, screen, version, mode, installer=None, initial=None):
        self.screen = screen
        self.version = version
        self.brand_color = 0
        self.version_color = 0
        self.page = 'settings'
        self.mode = mode
        self.focus = 0
        self.values = {
            'server': dict(SERVER_FIELDS),
            'client': dict(CLIENT_FIELDS),
        }
        if initial:
            self.values[mode].update(initial)
        self.installer = installer
        self.events = queue.Queue()
        self.failure = ''
        self.completed = False
        self.cancelled = True
        self.positions = {label: len(value) for label, value in self.fields()}
        self.errors = {}
        self.admin_password = None
        self.progress = 0
        self.next_step = 0.0

    def text(self, row, col, value, attr=0):
        height, width = self.screen.getmaxyx()
        if 0 <= row < height - 1 and 0 <= col < width - 1:
            self.screen.addnstr(row, col, value, width - col - 1, attr)

    def button(self, row, col, label, index):
        self.text(row, col, f'[ {label} ]', curses.A_REVERSE if self.focus == index else 0)

    def fields(self):
        return SERVER_FIELDS if self.mode == 'server' else CLIENT_FIELDS

    def render(self):
        self.screen.erase()
        cursor = None
        height, width = self.screen.getmaxyx()
        if height < 25 or width < 80:
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            self.text(0, 0, 'Resize terminal to at least 80 columns x 25 rows. Esc: quit.')
            self.screen.refresh()
            return False
        product = 'Autobricks PKI Server '
        version = self.version + ' '
        self.text(1, 2, product, curses.A_BOLD | self.brand_color)
        self.text(1, 2 + len(product), version, curses.A_BOLD | self.version_color)
        self.text(1, 2 + len(product) + len(version), '(C) 2026 Autobricks, Co.', curses.A_BOLD | self.brand_color)
        if self.page == 'settings':
            self.text(height - 2, 2, 'Tab: next   Shift-Tab: previous   Enter: select   Esc: cancel')
        elif self.page == 'done':
            self.text(height - 2, 2, 'Enter: finish')
        if self.page == 'settings':
            self.text(4, 2, 'Server Configuration' if self.mode == 'server' else 'Client Configuration', curses.A_BOLD)
            for index, (label, _) in enumerate(self.fields()):
                row = 6 + index * 2
                self.text(row, 4, label)
                value = self.values[self.mode][label]
                field_width = min(FIELD_LIMITS[label] + 1, width - 34)
                position = self.positions[label]
                offset = max(0, position - field_width + 1)
                shown = value[offset:offset + field_width].ljust(field_width)
                self.text(row, 29, shown, curses.A_REVERSE if self.focus == index else curses.A_UNDERLINE)
                hint = f'(max {FIELD_LIMITS[label]})' if 'port' not in label else '(1-65535)'
                hint_col = 29 + field_width + 2
                if hint_col + len(hint) < width - 1:
                    self.text(row, hint_col, hint)
                if self.focus == index:
                    cursor = (row, 29 + position - offset)
                    if label in self.errors:
                        self.text(18, 4, self.errors[label], curses.A_BOLD)
            count = len(self.fields())
            self.button(20, 4, 'Install', count)
            self.button(20, 22, 'Cancel', count + 1)
        elif self.page == 'installing':
            self.text(4, 2, 'Installing Autobricks PKI', curses.A_BOLD)
            steps = self.install_steps()
            for index, step in enumerate(steps):
                state = '[OK]' if index < self.progress else ('[>>]' if index == self.progress else '[  ]')
                self.text(7 + index * 2, 4, f'{state} {step}')
            percent = self.progress * 100 // len(steps)
            self.text(20, 4, '[' + '#' * (percent // 5) + ' ' * (20 - percent // 5) + f'] {percent}%')
        elif self.page == 'failed':
            self.text(5, 4, 'Installation Failed', curses.A_BOLD)
            import textwrap
            for index, line in enumerate(textwrap.wrap(self.failure, width - 8)[:10]):
                self.text(8 + index, 4, line)
            self.button(20, 4, 'Back', 0)
            self.button(20, 20, 'Cancel', 1)
        else:
            self.text(5, 4, 'Installation Complete', curses.A_BOLD)
            self.text(8, 4, 'Autobricks PKI server and client have been installed.' if self.mode == 'server' else 'Autobricks PKI client has been installed.')
            if self.mode == 'server':
                self.text(11, 4, 'ADMIN password: ' + (self.admin_password or ''), curses.A_BOLD)
                self.text(13, 4, 'Configuration: /etc/autobricks-pki/abpkid.env')
                self.text(14, 4, 'Setting: ABPKI_ADMIN_PASSWORD')
            self.button(20, 4, 'Finish', 0)
        try:
            curses.curs_set(1 if cursor else 0)
        except curses.error:
            pass
        if cursor:
            self.screen.move(*cursor)
        self.screen.refresh()
        return True

    def install_steps(self):
        # Visual simulation only. These labels never invoke installation operations.
        if self.mode == 'server':
            return ('Check service prerequisites', 'Prepare storage and server configuration',
                    'Initialize certificate authorities', 'Register the server DNS name',
                    'Configure local client and Root CA trust', 'Start server and client services')
        return ('Check server connection', 'Retrieve Root CA certificate',
                'Register OS trust', 'Save client settings', 'Start client service')

    def select(self):
        if self.page == 'settings':
            count = len(self.fields())
            if self.focus < count:
                self.focus += 1
            elif self.focus == count:
                self.errors = validate(self.mode, self.values[self.mode])
                if self.errors:
                    self.focus = next(i for i, (key, _) in enumerate(self.fields()) if key in self.errors)
                else:
                    self.page, self.focus = 'installing', 0
                    self.progress = 0
                    self.next_step = time.monotonic() + 0.4
                    if self.installer:
                        threading.Thread(target=self.install_worker, daemon=True).start()
            else:
                return False
        elif self.page == 'failed' and self.focus == 0:
            self.page, self.focus = 'settings', 0
        else:
            return False
        return True

    def install_worker(self):
        try:
            password = self.installer(dict(self.values[self.mode]), lambda step: self.events.put(('progress', step)))
            self.events.put(('done', password))
        except Exception as error:
            self.events.put(('error', str(error)))

    def run(self):
        self.screen.keypad(True)
        if curses.has_colors():
            curses.start_color()
            background = curses.COLOR_BLACK
            try:
                curses.use_default_colors()
                background = -1
            except curses.error:
                pass
            curses.init_pair(1, curses.COLOR_BLUE, background)
            curses.init_pair(2, curses.COLOR_GREEN, background)
            self.brand_color = curses.color_pair(1)
            self.version_color = curses.color_pair(2)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        while True:
            ready = self.render()
            self.screen.timeout(100 if self.page == 'installing' else -1)
            try:
                key = self.screen.get_wch()
            except curses.error:
                key = None
            if self.page == 'installing':
                if self.installer:
                    try:
                        event, value = self.events.get_nowait()
                    except queue.Empty:
                        continue
                    if event == 'progress':
                        self.progress = value
                    elif event == 'done':
                        self.admin_password = value
                        self.completed = True
                        self.cancelled = False
                        self.page, self.focus = 'done', 0
                    else:
                        self.failure = value
                        self.page, self.focus = 'failed', 0
                    continue
                if key == '\x1b':
                    break
                if ready and time.monotonic() >= self.next_step:
                    self.progress += 1
                    self.next_step = time.monotonic() + 0.4
                    if self.progress >= len(self.install_steps()):
                        if self.mode == 'server':
                            self.admin_password = ''.join(
                                secrets.choice(string.ascii_letters + string.digits)
                                for _ in range(16))
                        self.page, self.focus = 'done', 0
                continue
            if key == '\x1b':
                break
            if not ready or key == curses.KEY_RESIZE:
                continue
            count = len(self.fields()) + 2 if self.page == 'settings' else (2 if self.page == 'failed' else 1)
            if key in ('\t', curses.KEY_DOWN):
                self.focus = (self.focus + 1) % count
            elif key in (curses.KEY_BTAB, curses.KEY_UP):
                self.focus = (self.focus - 1) % count
            elif key in ('\n', '\r', curses.KEY_ENTER):
                if not self.select():
                    break
            elif self.page == 'settings' and self.focus < len(self.fields()):
                label = self.fields()[self.focus][0]
                value = self.values[self.mode][label]
                value, position, error = edit_value(label, value, self.positions[label], key)
                self.positions[label] = position
                self.values[self.mode][label] = value
                if error:
                    self.errors[label] = error
                elif error is not None:
                    self.errors.pop(label, None)
            elif key in (curses.KEY_LEFT, curses.KEY_RIGHT):
                self.focus = (self.focus + (1 if key == curses.KEY_RIGHT else -1)) % count


def main():
    parser = argparse.ArgumentParser(description='Preview PKI installation screens without installing or saving anything.')
    parser.add_argument('package', choices=('server', 'client'),
                        help='Preview the settings of the package being installed.')
    args = parser.parse_args()
    try:
        version = (Path(__file__).resolve().parents[2] / 'VERSION').read_text().strip()
    except OSError as error:
        parser.exit(1, f'Cannot read project VERSION: {error}\n')
    if not re.fullmatch(r'1\.0\.[0-9]{3,}', version):
        parser.exit(1, 'Invalid project VERSION; expected 1.0.NNN.\n')
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.exit(1, 'Run this preview in an interactive terminal.\n')
    try:
        curses.wrapper(lambda screen: Preview(screen, version, args.package).run())
    except KeyboardInterrupt:
        pass
    except curses.error as error:
        parser.exit(1, f'Terminal initialization failed: {error}\n')


if __name__ == '__main__':
    main()
