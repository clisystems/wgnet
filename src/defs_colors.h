/*********************************************************************
wgnet WireGuard network utility

Copyright (C) 2020 - Andrew Gaylo - drew@clisystems.com

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

*******************************************************************/
#ifndef __DEFS_COLORS__
#define __DEFS_COLORS__

// This header file can be used for setting output console colors
// on VT100 consoles.


#define BACKGROUND_COLOR_NORMAL	'4'
#define FOREGROUND_COLOR_NORMAL	'3'
#define FOREGROUND_COLOR_LIGHT	'9'

#define FGCOLORSET		FOREGROUND_COLOR_NORMAL
//#define FGCOLORSET		FOREGROUND_COLOR_LIGHT

#define VTCOLOR_BLACK	'0'
#define VTCOLOR_RED		'1'
#define VTCOLOR_GREEN	'2'
#define VTCOLOR_YELLOW	'3'
#define VTCOLOR_BLUE	'4'
#define VTCOLOR_MAGENTA	'5'
#define VTCOLOR_CYAN	'6'
#define VTCOLOR_GRAY	'7'
#define VTCOLOR_DEFAULT	'9'

#define FOREGROUND_COLOR(B,C)		printf("%c%c%c%c%c", 0x1B, '[', (B), (C),'m')
#define BACKGROUND_COLOR(C)		printf("%c%c%c%c%c", 0x1B, '[', BACKGROUND_COLOR_NORMAL, (C),'m')

#define RED()		FOREGROUND_COLOR(FGCOLORSET, VTCOLOR_RED)
#define GREEN()		FOREGROUND_COLOR(FGCOLORSET, VTCOLOR_GREEN)
#define YELLOW()	FOREGROUND_COLOR(FGCOLORSET, VTCOLOR_YELLOW)
#define BLUE()		FOREGROUND_COLOR(FGCOLORSET, VTCOLOR_BLUE)
#define WHITE()		FOREGROUND_COLOR(FGCOLORSET, VTCOLOR_GRAY)
#define MAGENTA()	FOREGROUND_COLOR(FGCOLORSET, VTCOLOR_MAGENTA)
#define DEFAULT()	FOREGROUND_COLOR(FGCOLORSET, VTCOLOR_GRAY)

#define NORMAL()	printf("%c%c%c%c", 0x1B, '[', '0', 'm')
#define BOLD()		printf("%c%c%c%c", 0x1B, '[', '1', 'm')



#endif
