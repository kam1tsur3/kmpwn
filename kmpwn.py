import sys
import os

def fsb(width, offset, data, padding, roop):
	payload = ""
	write_num = 0 
	write_all = 0
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
		write_num = ((((data >> (i*8*width)) & mask) + (1 << width*8)) - (write_all & mask) - padding)
		if write_num > (1 << width*8):
			write_num -= (1 << width*8) 
		payload += "%"
		payload += str(write_num)
		payload += "x%"
		payload += str(offset+i)
		payload += s
		write_all += write_num 
		
	return payload

def rot(s, num):
	n = ""
	for i in range(0, len(s)):
		c = ord(s[i])
		if c <= ord("z") and c >= ord("a"):
			c = ((c%ord("a") + num) % 26)+ord("a") 
		elif c <= ord("Z") and c >= ord("A"):
			c = ((c%ord("A") + num) % 26)+ord("A")
		n += chr(c)
	return n 

def b2d(s):
	r = 0 
	for i in range(0, len(s)):
		r = r << 1 
		if s[i] == '1':
			r += 1
	return r

def o2d(s):
	r = 0 
	for i in range(0, len(s)):
		r = r * 8 
		r += int(s[i])
	return r

# for house of corrosion
def offset2size(off):
	return ((off)*2-0x10)
