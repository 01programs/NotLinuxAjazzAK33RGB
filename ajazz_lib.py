#!/usr/bin/env python2

import operator
import sys
import types
from functools import reduce
from hex_values import *


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


def send_mode_packet(device, mode, verbose):
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


class KeyboardCommunication(object):
    def __init__(self, device, verbose):
        self.device = device
        self.verbose = verbose

    def __enter__(self):
        write_read(self.device, START_PKT, self.verbose)

    def __exit__(self, exc_type, exc_value, exc_traceback):
        print(exc_type, exc_value, exc_traceback)
        write_read(self.device, FINISH_PKT, self.verbose)


def send_mode(device, mode, verbose):
    if mode:
        assert mode in range(MAX_MODE + 1), \
            "Mode must be in range 1..%d" % MAX_MODE
        with KeyboardCommunication(device, verbose):
            send_mode_packet(device, mode, verbose)


def send_level(device, mode, level, verbose):
    assert level in range(MAX_LEVEL + 1), "Level must 0..%d" % MAX_LEVEL

    level_pkt[LEVEL_NDX] = level

    with KeyboardCommunication(device, verbose):
        send_mode_packet(device, mode, verbose)
        write_read(device, level_pkt, verbose)


def send_solid(device, mode, solid, verbose):
    check_rgb(solid)
    set_rgb(solid_color_pkt, SOLID_LED_NDX, solid)

    with KeyboardCommunication(device, verbose):
        send_mode_packet(device, mode, verbose)
        write_read(device, SOLID_PREFIX_PKT, verbose)
        write_read(device, solid_color_pkt, verbose)

def send_keys(device, mode, keys_rgbs, verbose):
    for (key, rgb) in keys_rgbs:
        if not key.lower() in KEYCODES:
            raise KeyError("No such key '%s'" % key)
        check_rgb(rgb)

    with KeyboardCommunication(device, verbose):
        send_mode_packet(device, mode, verbose)
        for (key, rgb) in keys_rgbs:
            set_lo_hi(key_pkt, KEY_CODE_NDX, KEYCODES[key.lower()])
            set_rgb(key_pkt, KEY_RGB_NDX,          rgb)
            write_read(device, key_pkt, verbose)

def send_file(device, mode, file, verbose):
    try:
        leds = parse_file(file)
    except (SyntaxError, ValueError) as error:
        sys.stderr.write("%s\n" % error)
        sys.exit(1)

    for led in leds:
        pkt_ndx = led[0] / LEDS_PER_PACKET
        led_ndx = led[0] % LEDS_PER_PACKET + FIRST_LED_NDX

        leds_pkts[pkt_ndx][led_ndx:led_ndx+3] = led[1]

    with KeyboardCommunication(device, verbose):
        send_mode_packet(device, mode,            verbose)
        write_read(device, LEDS_PREFIX_PKT, verbose)

        for pkt in leds_pkts:
            write_read(device, pkt, verbose)

def ajazz(device, mode, level, solid, keys, file, verbose):
    init_leds_pkts()

    if mode is not None:
        assert mode in range(1, MAX_MODE + 1), \
            "mode must be in range 1..%d" % MAX_MODE

    if mode and not (level or solid or keys or file):
        send_mode(device, mode, verbose)
    elif level is not None:
        send_level(device, mode, level, verbose)
    elif solid:
        send_solid(device, mode, solid, verbose)
    elif keys:
        send_keys(device, mode, keys, verbose)
    elif file:
        send_file(device, mode, file, verbose)


def key_names():
    for name in list(KEYCODES.keys()):
        print(" %s" % name)
    print('\n')


