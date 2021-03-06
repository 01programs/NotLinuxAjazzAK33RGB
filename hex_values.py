#!/usr/bin/env python2

KEYCODES = {
    'esc'           : (0x00, 0x00),
    'f1'            : (0x03, 0x00),
    'f2'            : (0x06, 0x00),
    'f3'            : (0x09, 0x00),
    'f4'            : (0x0C, 0x00),
    'f5'            : (0x0F, 0x00),
    'f6'            : (0x12, 0x00),
    'f7'            : (0x15, 0x00),
    'f8'            : (0x18, 0x00),
    'f9'            : (0x1B, 0x00),
    'f10'           : (0x1E, 0x00),
    'f11'           : (0x21, 0x00),
    'f12'           : (0x24, 0x00),
  # 'fn'            : (0x2A, 0x00),     # known not to work: 27 2A 9B A2 A5
    'del'           : (0xA8, 0x00),
    '`'             : (0x3F, 0x00),
    '~'             : (0x3F, 0x00),
    'backtick'      : (0x3F, 0x00),
    'tilde'         : (0x3F, 0x00),
    '1'             : (0x42, 0x00),
    '2'             : (0x45, 0x00),
    '3'             : (0x48, 0x00),
    '4'             : (0x4B, 0x00),
    '5'             : (0x4E, 0x00),
    '6'             : (0x51, 0x00),
    '7'             : (0x54, 0x00),
    '8'             : (0x57, 0x00),
    '9'             : (0x5A, 0x00),
    '0'             : (0x5D, 0x00),
    '-'             : (0x60, 0x00),
    'hyphen'        : (0x60, 0x00),
    '='             : (0x63, 0x00),
    'equal'         : (0x63, 0x00),
    'backspace'     : (0x66, 0x00),
    'bckspc'        : (0x66, 0x00),
    'home'          : (0x6C, 0x00),
    'tab'           : (0x7E, 0x00),
    'q'             : (0x81, 0x00),
    'w'             : (0x84, 0x00),
    'e'             : (0x87, 0x00),
    'r'             : (0x8A, 0x00),
    't'             : (0x8D, 0x00),
    'y'             : (0x90, 0x00),
    'u'             : (0x93, 0x00),
    'i'             : (0x96, 0x00),
    'o'             : (0x99, 0x00),
    'p'             : (0x9C, 0x00),
    '['             : (0x9F, 0x00),
    'open_bracket'  : (0x9F, 0x00),
    ']'             : (0xA2, 0x00),
    'close_bracket' : (0xA2, 0x00),
    '|'             : (0xA5, 0x00),
    '\\'            : (0xA5, 0x00),
    'backslash'     : (0xA5, 0x00),
    'page_up'       : (0x6F, 0x00),
    'pgup'          : (0x6F, 0x00),
    'cpslck'        : (0xBD, 0x00),
    'capslock'      : (0xBD, 0x00),
    'a'             : (0xC0, 0x00),
    's'             : (0xC3, 0x00),
    'd'             : (0xC6, 0x00),
    'f'             : (0xC9, 0x00),
    'g'             : (0xCC, 0x00),
    'h'             : (0xCF, 0x00),
    'j'             : (0xD2, 0x00),
    'k'             : (0xD5, 0x00),
    'l'             : (0xD8, 0x00),
    ';'             : (0xDB, 0x00),
    'semicolon'     : (0xDB, 0x00),
    ':'             : (0xDB, 0x00),
    'colon'         : (0xDB, 0x00),
    "'"             : (0xDE, 0x00),
    'apostrophe'    : (0xDE, 0x00),
    '"'             : (0xDE, 0x00),
    'quote'         : (0xDE, 0x00),
    'enter'         : (0xE4, 0x00),
    'return'        : (0xE4, 0x00),
    'pgdwn'         : (0xAE, 0x00),
    'page_down'     : (0xAE, 0x00),
    'shftl'         : (0xFC, 0x00),
    'left_shift'    : (0xFC, 0x00),
    'z'             : (0x02, 0x01),
    'x'             : (0x05, 0x01),
    'c'             : (0x08, 0x01),
    'v'             : (0x0B, 0x01),
    'b'             : (0x0E, 0x01),
    'n'             : (0x11, 0x01),
    'm'             : (0x14, 0x01),
    ','             : (0x17, 0x01),
    'comma'         : (0x17, 0x01),
    '.'             : (0x1A, 0x01),
    'period'        : (0x1A, 0x01),
    '/'             : (0x1D, 0x01),
    'slash'         : (0x1D, 0x01),
    'shftr'         : (0x23, 0x01),
    'right_shift'   : (0x23, 0x01),
    'up'            : (0x29, 0x01),
    'end'           : (0xAB, 0x00),     # guess, all 2b,2f,32,35,38 wrong
    'ctrll'         : (0x3B, 0x01),
    'left_ctrl'     : (0x3B, 0x01),
    'wndws'         : (0x3E, 0x01),
    'windows'       : (0x3E, 0x01),
    'altl'          : (0x41, 0x01),
    'left_alt'      : (0x41, 0x01),
    ' '             : (0x44, 0x01),
    'spc'           : (0x44, 0x01),
    'space'         : (0x44, 0x01),
    'altr'          : (0x47, 0x01),
    'right_alt'     : (0x47, 0x01),
    'ctrlr'         : (0x53, 0x01),
    'right_ctrl'    : (0x53, 0x01),
    'left'          : (0x65, 0x01),
    'down'          : (0x68, 0x01),
    'right'         : (0x6B, 0x01),
}


PACKET_SIZE = 64

START_PKT =        (0x04, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

FINISH_PKT =       (0x04, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

mode_pkt =         [0x04, 0x0d, 0x00, 0x06, 0x01, 0x00, 0x00, 0x00,
                    0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

level_pkt =        [0x04, 0x00, 0x00, 0x06, 0x01, 0x01, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

SOLID_PREFIX_PKT = (0x04, 0x0b, 0x00, 0x06, 0x01, 0x04, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

solid_color_pkt =  [0x04, 0x00, 0x00, 0x06, 0x03, 0x05, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

key_pkt =          [0x04, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

LEDS_PREFIX_PKT =  (0x04, 0x11, 0x00, 0x06, 0x03, 0x08, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

leds_pkts =        [    [0x04, 0x00, 0x00, 0x11, 0x36] + 59 * [0]
                    for ndx in range(7)                          ]

SOLID_MODE       = 0x06
CUSTOM_MODE      = 0x14

# packet ineces
CHECKSUM_NDX = 1
FIRST_DATA_NDX = 3
LEVEL_NDX = 8
MODE_NDX = 8
SOLID_LED_NDX = 8
KEY_CODE_NDX = 5
KEY_RGB_NDX = 8
LEDS_PER_PKT_NDX = 5
FIRST_LED_NDX = 8
MAX_LEVEL = 5
MAX_MODE = CUSTOM_MODE
MODE_NAMES = {'solid': SOLID_MODE,
              'custom': CUSTOM_MODE}


LEDS_PER_PACKET = 0x36
