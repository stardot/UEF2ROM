"""
Copyright (C) 2018 David Boddie <david@boddie.org.uk>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

def key_check(direction, keycode):

    code = (
        "\n"
        "    cpx #%i\n"
        "    bne not_%s\n"
        ) % (255 - int(keycode), keycode)
    l = 4
    
    d = direction.lower()
    
    if d in "dlru":
        if d in "lr":
            code += (
                "    lda #4\n"
                "    jsr bytev_read_analogue\n"
                )
            l += 5
        else:
            code += (
                "    lda #5\n"
                "    jsr bytev_read_analogue\n"
                )
            l += 5
        
        if d in "dr":
            code += (
                "    cmp #75\n"
                "    bcc bytev_key_pressed\n"
                "    bcs return_via_old_bytev_pop\n"
                )
            l += 6
        else:
            code += (
                "    cmp #161\n"
                "    bcs bytev_key_pressed\n"
                "    bcc return_via_old_bytev_pop\n"
                )
            l += 6
    else:
        code += (
            "    lda $fc72\n"
            "    and #$10\n"
            "    beq bytev_key_pressed\n"
            )
        l += 7
    
    code += (
        "    not_%s:\n"
        ) % keycode
    
    return code, l
