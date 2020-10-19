#!/usr/bin/env python2

import argparse
import sys
from functools import reduce
from hex_values import *
from ajazz_lib import *

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
