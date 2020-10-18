#!/usr/bin/env python2

import argparse
import operator
import sys
import types
from functools import reduce
from hex_values import *

COPYRIGHT = '''
Copyright 2018 Mark R. Rubin
This is free software with ABSOLUTELY NO WARRANTY.
'''

NO_WARRANTY = '''
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/gpl.html>
'''

WARNING = '''
This is experimental software. Using it will void any and all warranties
from Electronic Technologyu Co., Ltd. or any other entity. This software may
permanently damage your keyboard. By typing "accept" you assume all risk and
agree to hold harmless it's author, the copyright holder, and any and all
other entities.

Type "accept" to continue, or anything else to exit.
'''


MODES = [
    # rainbow/color, left/right, speed,
    ('Go with the stream', 'Diagonal line moving horizontally'),
    # rainbow/color, left/right, speed,
    ('Clouds fly', 'Arrow tip moving horizontally'),
    # rainbow/color, left/right, speed,
    ('Winding paths', 'Circular motion around the keyboard\'s center - Rectangular tornado'),
    ('Trial of the light', 'Homogeneous lighting fading through all RGB colors without going to black inbetween'),  # speed
    # rainbow/color, speed,
    ('Breathing', 'Fading from the selected color/rainbow to black and back'),
    ('Normally on', 'Lighting on, no effects'),  # color
    # rainbow/color, speed,
    ('Pass without trace', 'Pressed keys (can be multiple at once) become lit and than fade out, the rest of the keyboard is not lit'),
    # rainbow/color, speed,
    ('Ripple graff', 'Ripple starting from the pressed key (can be multiple at once), the rest of the keyboard is not lit'),
    # rainbow/color, speed,
    ('Fast run without trace',
     'Same as `Pass without trace` but the effect propagates horizontally'),
    ('Snow winter jasmin', 'Every key is initiated with another (nicely desaturated) color (or off). The colors change at random times, making it look like raindrops from above'),  # speed,
    ('Flowers blooming',
     'All keys have a random RGB color and fade through all colors in sync'),  # speed,
    # left/right, speed,
    ('Swift action', 'Rainbow pattern moving vertically over the keyboard'),
    ('Hurricane', 'Standing (triangle) wave pattern'),  # rainbow/color, speed,
    # rainbow/color, speed,
    ('Accumulate', 'Implosion to explosion with buildup in the middle before the explosion part'),
    # rainbow/color, speed,
    ('Digital Times',
     'Rain animation/the matrix letter raining thing. [Turn green for extra hacking speed]'),
    ('Surmount', 'Keyboard is homogeneously colored but shifts the color to a more saturated variant of the selected color depending on your typing speed'),  # four colors available
    # rainbow/color,
    ('Both ways',
     'Tilted line bouncing horizontally. [Turn red for K.I.T.T. from Knight Rider]'),
    ('Fast and the Furious',
     'Solid RGB rainbow circles propagating from/to the center'),  # inward/outward
    # color, background color, preset
    ('Custom backlit mode',
     'Set individual key colors and base color. Supports presets/(sub-)modes'),
]
# REPORT RATE (the origianl software detects modechanges performed on the keyboard)

VERSION = (0, 1, 0)

CHECKSUM_NDX = 1
FIRST_DATA_NDX = 3

MAX_LEVEL = 5
LEVEL_NDX = 8

MAX_MODE = CUSTOM_MODE
MODE_NAMES = {'solid': SOLID_MODE,
              'custom': CUSTOM_MODE}
MODE_NDX = 8

SOLID_LED_NDX = 8

KEY_CODE_NDX = 5
KEY_RGB_NDX = 8

LEDS_PER_PACKET = 0x36
LEDS_PER_PKT_NDX = 5
FIRST_LED_NDX = 8


def lo_hi_16(lo_hi):
    return (lo_hi[1] << 8) | lo_hi[0]


def to_byte(s):
    base = 16 if s.lower().startswith('0x') else 10
    return int(s, base)


def rgb_strings_to_bytes(raw):
    bytes = [to_byte(e) for e in raw]
    assert max(bytes) <= 0xff and min(bytes) >= 0, "Bad rgb value in %s" % raw
    return bytes


def set_16_bit(packet, index, short):
    packet[index] = short & 0x00ff
    packet[index + 1] = (short & 0xff00) >> 8


def set_lo_hi(packet, index, lo_hi):
    packet[index:index+2] = lo_hi


def check_rgb(rgb):
    for val in rgb:
        assert val >= 0 and val <= 255, "Bad rgb value in %s" % rgb


def set_rgb(packet, index, rgb):
    packet[index:index+3] = rgb


def init_leds_pkts():
    for (ndx, pkt) in enumerate(leds_pkts):
        set_16_bit(pkt, LEDS_PER_PKT_NDX, ndx * LEDS_PER_PACKET)


def print_packet(caption, packet):
    print("%s:\n" % caption)
    for (ndx, byte) in enumerate(packet):
        print("%02x" % byte)
        print(" " if (ndx + 1) % 16 else "\n")


def write_read(device, packet, verbose):
    if issubclass(type(packet), list):
        checksum = reduce(operator.add, packet[FIRST_DATA_NDX:])
        set_16_bit(packet, CHECKSUM_NDX, checksum)

    if verbose:
        print_packet("send", packet)

    device.write(bytearray(packet))

    response = device.read(PACKET_SIZE)

    if verbose:
        print_packet("recv", [ord(byte) for byte in response])


def do_mode_packet(device, mode, verbose):
    if mode:
        mode_pkt[MODE_NDX] = mode
        write_read(device, mode_pkt, verbose)


def check_version(fields):
    (major, minor, micro) = [int(field) for field in fields[1:4]]
    if major != VERSION[0] or minor > VERSION[1]:
        raise ValueError("version mismatch, file: %s  code: %s"
                         % ((major, minor, micro), VERSION))


def rgb(hexs, filename, linenum):
    try:
        assert len(hexs) == 3
        rgb = tuple([int(hex, 16) for hex in hexs])
    except:
        raise ValueError("bad RGB hex triplet %s, line %d of file %s ("
                         "must be 3 hexidecimal numbers in range 00..ff)"
                         % (hexs, linenum, filename))
    return rgb


def parse_file(file):
    colors = {}
    leds = []
    sets = set()
    default = None
    linenum = 0

    for line in file:
        linenum += 1
        fields = line.split()

        if len(fields) < 2:
            continue

        if fields[0] in KEYCODES:
            if fields[1].startswith('/'):
                try:
                    led = colors[fields[1]]
                except:
                    raise ValueError("Unknown color %s, line %d of file %s"
                                     % (fields[1], linenum, file.name))
            else:
                led = rgb(fields[1:4], file.name, linenum)

            leds.append((lo_hi_16(KEYCODES[fields[0]]), led))
            sets.add(fields[0])

        elif fields[0].startswith('/') and fields[0] != '/':
            if fields[0].lower() == '/default':
                default = rgb(fields[1:4], file.name, linenum)
            else:
                colors[fields[0]] = rgb(fields[1:4], file.name, linenum)

        elif fields[0].startswith('#'):
            continue

        elif fields[0].lower() == 'version':
            check_version(fields)

        else:
            raise SyntaxError("Unknown key or syntax error, file %s line %d"
                              % (file.name, linenum))

    if default:
        for key in list(KEYCODES.keys()):
            if not key in sets:
                leds.append((lo_hi_16(KEYCODES[key]), default))

    return leds


def do_mode(device, mode, verbose):
    if mode:
        assert mode in range(MAX_MODE + 1), \
            "Mode must be in range 1..%d" % MAX_MODE
        write_read(device, START_PKT, verbose)
        do_mode_packet(device, mode, verbose)
        write_read(device, FINISH_PKT, verbose)


def do_level(device, mode, level, verbose):
    assert level in range(MAX_LEVEL + 1), "Level must 0..%d" % MAX_LEVEL

    level_pkt[LEVEL_NDX] = level

    write_read(device, START_PKT, verbose)
    do_mode_packet(device, mode, verbose)
    write_read(device, level_pkt, verbose)
    write_read(device, FINISH_PKT, verbose)


def do_solid(device, mode, solid, verbose):
    check_rgb(solid)
    set_rgb(solid_color_pkt, SOLID_LED_NDX, solid)

    write_read(device, START_PKT, verbose)
    do_mode_packet(device, mode, verbose)
    write_read(device, SOLID_PREFIX_PKT, verbose)
    write_read(device, solid_color_pkt, verbose)
    write_read(device, FINISH_PKT, verbose)


def do_keys(device, mode, keys_rgbs, verbose):
    for (key, rgb) in keys_rgbs:
        if not key.lower() in KEYCODES:
            raise KeyError("No such key '%s'" % key)
        check_rgb(rgb)

    write_read(device, START_PKT, verbose)
    do_mode_packet(device, mode, verbose)

    for (key, rgb) in keys_rgbs:
        set_lo_hi(key_pkt, KEY_CODE_NDX, KEYCODES[key.lower()])
        set_rgb(key_pkt, KEY_RGB_NDX,          rgb)

        write_read(device, key_pkt, verbose)

    write_read(device, FINISH_PKT, verbose)


def do_file(device, mode, file, verbose):
    try:
        leds = parse_file(file)
    except (SyntaxError, ValueError) as error:
        sys.stderr.write("%s\n" % error)
        sys.exit(1)

    for led in leds:
        pkt_ndx = led[0] / LEDS_PER_PACKET
        led_ndx = led[0] % LEDS_PER_PACKET + FIRST_LED_NDX

        leds_pkts[pkt_ndx][led_ndx:led_ndx+3] = led[1]

    write_read(device, START_PKT, verbose)
    do_mode_packet(device, mode,            verbose)
    write_read(device, LEDS_PREFIX_PKT, verbose)

    for pkt in leds_pkts:
        write_read(device, pkt, verbose)

    write_read(device, FINISH_PKT, verbose)


def ajazz(device, mode, level, solid, keys, file, verbose):
    init_leds_pkts()

    if mode is not None:
        assert mode in range(1, MAX_MODE + 1), \
            "mode must be in range 1..%d" % MAX_MODE

    if mode and not (level or solid or keys or file):
        do_mode(device, mode, verbose)
    elif level is not None:
        do_level(device, mode, level, verbose)
    elif solid:
        do_solid(device, mode, solid, verbose)
    elif keys:
        do_keys(device, mode, keys, verbose)
    elif file:
        do_file(device, mode, file, verbose)


def key_names():
    for name in list(KEYCODES.keys()):
        print(" %s" % name)
    print('\n')


def parse_commandline():
    parser = argparse.ArgumentParser(prog=sys.argv[0])

    def mode(text):
        mode_name = text.lower()
        if mode_name in list(MODE_NAMES.keys()):
            return MODE_NAMES[mode_name]
        else:
            try:
                mode = int(text)
                assert mode in range(1, MAX_MODE + 1)
            except:
                raise argparse.ArgumentTypeError("mode must be one of %s "
                                                 "or number from 1..%d"
                                                 % (','.join(list(MODE_NAMES.keys())),
                                                    MAX_MODE))
            return mode

    def level(text):
        try:
            level = int(text)
            assert level in range(MAX_LEVEL + 1)
        except:
            raise argparse.ArgumentTypeError("brightness level must be "
                                             "number 0..%d" % MAX_LEVEL)
        return level

    class Rgb(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            try:
                rgb = rgb_strings_to_bytes(values)
            except:
                parser.error("bad RGB '%s'" %
                             " ".join(values))  # not ArgTypErr
            setattr(namespace, self.dest, rgb)

    class KeyRgb(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            key = values[0]
            rgb = values[1:4]
            if not key in KEYCODES:
                parser.error("unknown key '%s'\n" %
                             key)  # not ArgumentTypeError
            try:
                key_rgb = (values[0], rgb_strings_to_bytes(rgb))
            except:
                parser.error("bad RGB '%s'\n" % " ".join(rgb))  # not ArgTypErr
            if getattr(namespace, 'keys', None) is None:
                setattr(namespace, 'keys', [])
            getattr(namespace, 'keys').append(key_rgb)
            setattr(namespace, self.dest, key_rgb)

    parser.add_argument('-d', '--device',
                        required=True,
                        type=argparse.FileType('r+'),
                        help="/dev/hidrawN")

    parser.add_argument('-m', '--mode',
                        nargs='?',
                        type=mode,
                        default=None,
                        help="solid|custom|<1-%d>" % MAX_MODE)

    exclsv = parser.add_mutually_exclusive_group(required=False)

    exclsv.add_argument('-l', '--level',
                        nargs='?',
                        type=level,
                        default=None,
                        help="<brightness level> (0..%d)" % MAX_LEVEL)

    exclsv.add_argument('-s', '--solid',
                        nargs=3,
                        action=Rgb,
                        help="<r> <g> <b>")

    exclsv.add_argument('-k', '--key',
                        nargs=4,
                        action=KeyRgb,
                        help="<key> <r> <g> <b>")

    parser.add_argument('--keys',
                        action='store_const',
                        const=None,
                        default=None,
                        help=argparse.SUPPRESS)

    exclsv.add_argument('-f', '--file',
                        nargs='?',
                        type=argparse.FileType('r'),
                        help="key+color file ")

    exclsv.add_argument('--names',
                        action='store_true',
                        help="print key names for --file file")

    parser.add_argument('-A', '--accept',
                        action='store_true',
                        help="suppress warning message")

    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help="print binary packets sent to and received "
                             "from keyboard")

    exclsv.add_argument('--version',
                        action='version',
                        version=str(VERSION),
                        help="print file format version")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_commandline()

    # can't do this with argparse.add_mutually_exclusive_group(required=True)
    # because --mode can be standalone or added to other options
    if not (args.mode
            or args.level
            or (args.level == 0)
            or args.solid
            or args.key
            or args.file
            or args.names):
        sys.stderr.write(
            "Specify -m and/or one of -l, -s, -k, -f (or --help)\n")
        sys.exit(1)

    if not args.accept:
        print(COPYRIGHT)
        print(NO_WARRANTY)
        print(WARNING)
        if sys.stdin.readline() != "accept\n":
            sys.stderr.write("\nexiting ...\n")
            sys.exit(1)
        sys.stderr.write('\n')

    if args.names:
        key_names()
        sys.exit(0)

    ajazz(args.device,
          args.mode,
          args.level,
          args.solid,
          args.keys,
          args.file,
          args.verbose)
