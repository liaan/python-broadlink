#!/usr/bin/python
# -*- coding: utf8 -*-

from datetime import datetime
from Crypto.Cipher import AES
import time
import random
import socket
import threading
import parse
import struct

def gendevice(devtype, host, mac):
  print format(devtype,'02x')
  if devtype == 0: # SP1
    return sp1(host=host, mac=mac)
  if devtype == 0x2711: # SP2
    return sp2(host=host, mac=mac)
  if devtype == 0x2719 or devtype == 0x7919 or devtype == 0x271a or devtype == 0x791a: # Honeywell SP2
    return sp2(host=host, mac=mac)
  if devtype == 0x2720: # SPMini
    return sp2(host=host, mac=mac)
  elif devtype == 0x753e: # SP3
    return sp2(host=host, mac=mac)
  elif devtype == 0x2728: # SPMini2
    return sp2(host=host, mac=mac)
  elif devtype == 0x2733 or devtype == 0x273e: # OEM branded SPMini
    return sp2(host=host, mac=mac)
  elif devtype >= 0x7530 and devtype <= 0x7918: # OEM branded SPMini2
    return sp2(host=host, mac=mac)
  elif devtype == 0x2736: # SPMiniPlus
    return sp2(host=host, mac=mac)
  elif devtype == 0x2712: # RM2
    return rm(host=host, mac=mac)
  elif devtype == 0x2737: # RM Mini
    return rm(host=host, mac=mac)
  elif devtype == 0x273d: # RM Pro Phicomm
    return rm(host=host, mac=mac)
  elif devtype == 0x2783: # RM2 Home Plus
    return rm(host=host, mac=mac)
  elif devtype == 0x277c: # RM2 Home Plus GDT
    return rm(host=host, mac=mac)
  elif devtype == 0x272a: # RM2 Pro Plus
    return rm(host=host, mac=mac)
  elif devtype == 0x2787: # RM2 Pro Plus2
    return rm(host=host, mac=mac)
  elif devtype == 0x278b: # RM2 Pro Plus BL
    return rm(host=host, mac=mac)
  elif devtype == 0x278f: # RM Mini Shate
    return rm(host=host, mac=mac)
  elif devtype == 0x2714: # A1
    return a1(host=host, mac=mac)
  elif devtype == 0x4EB5: # MP1
    return mp1(host=host, mac=mac)
  elif devtype == 0x4E2a: # Danham Bush
    return ac_db(host=host, mac=mac)
  else:
    return device(host=host, mac=mac)

def discover(timeout=None, local_ip_address=None):
  if local_ip_address is None:
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.connect(('8.8.8.8', 53))  # connecting to a UDP address doesn't send packets
      local_ip_address = s.getsockname()[0]
  address = local_ip_address.split('.')
  cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
  cs.bind((local_ip_address,0))
  port = cs.getsockname()[1]
  starttime = time.time()

  devices = []

  timezone = int(time.timezone/-3600)
  packet = bytearray(0x30)

  year = datetime.now().year

  if timezone < 0:
    packet[0x08] = 0xff + timezone - 1
    packet[0x09] = 0xff
    packet[0x0a] = 0xff
    packet[0x0b] = 0xff
  else:
    packet[0x08] = timezone
    packet[0x09] = 0
    packet[0x0a] = 0
    packet[0x0b] = 0
  packet[0x0c] = year & 0xff
  packet[0x0d] = year >> 8
  packet[0x0e] = datetime.now().minute
  packet[0x0f] = datetime.now().hour
  subyear = str(year)[2:]
  packet[0x10] = int(subyear)
  packet[0x11] = datetime.now().isoweekday()
  packet[0x12] = datetime.now().day
  packet[0x13] = datetime.now().month
  packet[0x18] = int(address[0])
  packet[0x19] = int(address[1])
  packet[0x1a] = int(address[2])
  packet[0x1b] = int(address[3])
  packet[0x1c] = port & 0xff
  packet[0x1d] = port >> 8
  packet[0x26] = 6
  checksum = 0xbeaf

  for i in range(len(packet)):
      checksum += packet[i]
  checksum = checksum & 0xffff
  packet[0x20] = checksum & 0xff
  packet[0x21] = checksum >> 8

  cs.sendto(packet, ('255.255.255.255', 80))
  if timeout is None:
    response = cs.recvfrom(1024)
    responsepacket = bytearray(response[0])
    host = response[1]
    mac = responsepacket[0x3a:0x40]
    devtype = responsepacket[0x34] | responsepacket[0x35] << 8
    return gendevice(devtype, host, mac)
  else:
    while (time.time() - starttime) < timeout:
      cs.settimeout(timeout - (time.time() - starttime))
      try:
        response = cs.recvfrom(1024)
      except socket.timeout:
        return devices
      responsepacket = bytearray(response[0])
      
      print ":".join("{:02x}".format(c) for c in responsepacket)

      host = response[1]
      devtype = responsepacket[0x34] | responsepacket[0x35] << 8
      mac = responsepacket[0x3a:0x40]
      dev = gendevice(devtype, host, mac)
      devices.append(dev)
    return devices


class device:
  def __init__(self, host, mac, timeout=10):
    self.host = host
    self.mac = mac
    self.timeout = timeout
    self.count = random.randrange(0xffff)
    self.key = bytearray([0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02])
    self.iv = bytearray([0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58])
    self.id = bytearray([0, 0, 0, 0])
    self.cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    self.cs.bind(('',0))
    self.type = "Unknown"
    self.lock = threading.Lock()

  def auth(self):
    payload = bytearray(0x50)
    payload[0x04] = 0x31
    payload[0x05] = 0x31
    payload[0x06] = 0x31
    payload[0x07] = 0x31
    payload[0x08] = 0x31
    payload[0x09] = 0x31
    payload[0x0a] = 0x31
    payload[0x0b] = 0x31
    payload[0x0c] = 0x31
    payload[0x0d] = 0x31
    payload[0x0e] = 0x31
    payload[0x0f] = 0x31
    payload[0x10] = 0x31
    payload[0x11] = 0x31
    payload[0x12] = 0x31
    payload[0x1e] = 0x01
    payload[0x2d] = 0x01
    payload[0x30] = ord('T')
    payload[0x31] = ord('e')
    payload[0x32] = ord('s')
    payload[0x33] = ord('t')
    payload[0x34] = ord(' ')
    payload[0x35] = ord(' ')
    payload[0x36] = ord('1')

    response = self.send_packet(0x65, payload)

    enc_payload = response[0x38:]

    aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
    payload = aes.decrypt(bytes(enc_payload))

    if not payload:
     return False

    key = payload[0x04:0x14]
    if len(key) % 16 != 0:
     return False

    self.id = payload[0x00:0x04]
    self.key = key
    return True

  def get_type(self):
    return self.type

  def send_packet(self, command, payload):
    self.count = (self.count + 1) & 0xffff
    packet = bytearray(0x38)
    packet[0x00] = 0x5a
    packet[0x01] = 0xa5
    packet[0x02] = 0xaa
    packet[0x03] = 0x55
    packet[0x04] = 0x5a
    packet[0x05] = 0xa5
    packet[0x06] = 0xaa
    packet[0x07] = 0x55
    packet[0x24] = 0x2a #==> Type
    packet[0x25] = 0x4e #==> Type
    packet[0x26] = command
    packet[0x28] = self.count & 0xff
    packet[0x29] = self.count >> 8
    packet[0x2a] = self.mac[0]
    packet[0x2b] = self.mac[1]
    packet[0x2c] = self.mac[2]
    packet[0x2d] = self.mac[3]
    packet[0x2e] = self.mac[4]
    packet[0x2f] = self.mac[5]
    packet[0x30] = self.id[0]
    packet[0x31] = self.id[1]
    packet[0x32] = self.id[2]
    packet[0x33] = self.id[3]

    checksum = 0xbeaf
    for i in range(len(payload)):
      checksum += payload[i]
      checksum = checksum & 0xffff

    aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
    payload = aes.encrypt(bytes(payload))

    packet[0x34] = checksum & 0xff
    packet[0x35] = checksum >> 8

    for i in range(len(payload)):
      packet.append(payload[i])

    checksum = 0xbeaf
    for i in range(len(packet)):
      checksum += packet[i]
      checksum = checksum & 0xffff
    packet[0x20] = checksum & 0xff
    packet[0x21] = checksum >> 8

    print 'Sending Packet:\n'+''.join(format(x, '02x') for x in packet)+"\n"
    starttime = time.time()
    with self.lock:
      while True:
        try:
          self.cs.sendto(packet, self.host)
          self.cs.settimeout(1)
          response = self.cs.recvfrom(1024)

          break
        except socket.timeout:
          if (time.time() - starttime) < self.timeout:
            pass
          raise
    return bytearray(response[0])


class mp1(device):
  def __init__ (self, host, mac):
    device.__init__(self, host, mac)
    self.type = "MP1"

  def set_power_mask(self, sid_mask, state):
    """Sets the power state of the smart power strip."""

    packet = bytearray(16)
    packet[0x00] = 0x0d
    packet[0x02] = 0xa5
    packet[0x03] = 0xa5
    packet[0x04] = 0x5a
    packet[0x05] = 0x5a
    packet[0x06] = 0xb2 + ((sid_mask<<1) if state else sid_mask)
    packet[0x07] = 0xc0
    packet[0x08] = 0x02
    packet[0x0a] = 0x03
    packet[0x0d] = sid_mask
    packet[0x0e] = sid_mask if state else 0

    response = self.send_packet(0x6a, packet)

    err = response[0x22] | (response[0x23] << 8)

  def set_power(self, sid, state):
    """Sets the power state of the smart power strip."""
    sid_mask = 0x01 << (sid - 1)
    return self.set_power_mask(sid_mask, state)

  def check_power(self):
    """Returns the power state of the smart power strip."""
    packet = bytearray(16)
    packet[0x00] = 0x0a
    packet[0x02] = 0xa5
    packet[0x03] = 0xa5
    packet[0x04] = 0x5a
    packet[0x05] = 0x5a
    packet[0x06] = 0xae
    packet[0x07] = 0xc0
    packet[0x08] = 0x01

    response = self.send_packet(0x6a, packet)
    err = response[0x22] | (response[0x23] << 8)
    if err == 0:
      aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
      payload = aes.decrypt(bytes(response[0x38:]))
      if type(payload[0x4]) == int:
        state = payload[0x0e]
      else:
        state = ord(payload[0x0e])
      data = {}
      data['s1'] = bool(state & 0x01)
      data['s2'] = bool(state & 0x02)
      data['s3'] = bool(state & 0x04)
      data['s4'] = bool(state & 0x08)
      return data


class sp1(device):
  def __init__ (self, host, mac):
    device.__init__(self, host, mac)
    self.type = "SP1"

  def set_power(self, state):
    packet = bytearray(4)
    packet[0] = state
    self.send_packet(0x66, packet)


class sp2(device):
  def __init__ (self, host, mac):
    device.__init__(self, host, mac)
    self.type = "SP2"

  def set_power(self, state):
    """Sets the power state of the smart plug."""
    packet = bytearray(16)
    packet[0] = 2
    packet[4] = 1 if state else 0
    self.send_packet(0x6a, packet)

  def check_power(self):
    """Returns the power state of the smart plug."""
    packet = bytearray(16)
    packet[0] = 1
    response = self.send_packet(0x6a, packet)
    err = response[0x22] | (response[0x23] << 8)
    if err == 0:
      aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
      payload = aes.decrypt(bytes(response[0x38:]))
      return bool(payload[0x4])

class a1(device):
  def __init__ (self, host, mac):
    device.__init__(self, host, mac)
    self.type = "A1"

  def check_sensors(self):
    packet = bytearray(16)
    packet[0] = 1
    response = self.send_packet(0x6a, packet)
    err = response[0x22] | (response[0x23] << 8)
    if err == 0:
      data = {}
      aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
      payload = aes.decrypt(bytes(response[0x38:]))
      if type(payload[0x4]) == int:
        data['temperature'] = (payload[0x4] * 10 + payload[0x5]) / 10.0
        data['humidity'] = (payload[0x6] * 10 + payload[0x7]) / 10.0
        light = payload[0x8]
        air_quality = payload[0x0a]
        noise = payload[0xc]
      else:
        data['temperature'] = (ord(payload[0x4]) * 10 + ord(payload[0x5])) / 10.0
        data['humidity'] = (ord(payload[0x6]) * 10 + ord(payload[0x7])) / 10.0
        light = ord(payload[0x8])
        air_quality = ord(payload[0x0a])
        noise = ord(payload[0xc])
      if light == 0:
        data['light'] = 'dark'
      elif light == 1:
        data['light'] = 'dim'
      elif light == 2:
        data['light'] = 'normal'
      elif light == 3:
        data['light'] = 'bright'
      else:
        data['light'] = 'unknown'
      if air_quality == 0:
        data['air_quality'] = 'excellent'
      elif air_quality == 1:
        data['air_quality'] = 'good'
      elif air_quality == 2:
        data['air_quality'] = 'normal'
      elif air_quality == 3:
        data['air_quality'] = 'bad'
      else:
        data['air_quality'] = 'unknown'
      if noise == 0:
        data['noise'] = 'quiet'
      elif noise == 1:
        data['noise'] = 'normal'
      elif noise == 2:
        data['noise'] = 'noisy'
      else:
        data['noise'] = 'unknown'
      return data

  def check_sensors_raw(self):
    packet = bytearray(16)
    packet[0] = 1
    response = self.send_packet(0x6a, packet)
    err = response[0x22] | (response[0x23] << 8)
    if err == 0:
      data = {}
      aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
      payload = aes.decrypt(bytes(response[0x38:]))
      if type(payload[0x4]) == int:
        data['temperature'] = (payload[0x4] * 10 + payload[0x5]) / 10.0
        data['humidity'] = (payload[0x6] * 10 + payload[0x7]) / 10.0
        data['light'] = payload[0x8]
        data['air_quality'] = payload[0x0a]
        data['noise'] = payload[0xc]
      else:
        data['temperature'] = (ord(payload[0x4]) * 10 + ord(payload[0x5])) / 10.0
        data['humidity'] = (ord(payload[0x6]) * 10 + ord(payload[0x7])) / 10.0
        data['light'] = ord(payload[0x8])
        data['air_quality'] = ord(payload[0x0a])
        data['noise'] = ord(payload[0xc])
      return data


class rm(device):
  def __init__ (self, host, mac):
    device.__init__(self, host, mac)
    self.type = "RM2"

  def check_data(self):
    packet = bytearray(16)
    packet[0] = 4
    response = self.send_packet(0x6a, packet)
    err = response[0x22] | (response[0x23] << 8)
    if err == 0:
      aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
      payload = aes.decrypt(bytes(response[0x38:]))
      return payload[0x04:]

  def send_data(self, data):
    packet = bytearray([0x02, 0x00, 0x00, 0x00])
    packet += data
    self.send_packet(0x6a, packet)

  def enter_learning(self):
    packet = bytearray(16)
    packet[0] = 3
    self.send_packet(0x6a, packet)

  def check_temperature(self):
    packet = bytearray(16)
    packet[0] = 1
    response = self.send_packet(0x6a, packet)
    err = response[0x22] | (response[0x23] << 8)
    if err == 0:
      aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
      payload = aes.decrypt(bytes(response[0x38:]))
      if type(payload[0x4]) == int:
        temp = (payload[0x4] * 10 + payload[0x5]) / 10.0
      else:
        temp = (ord(payload[0x4]) * 10 + ord(payload[0x5])) / 10.0
      return temp
	  
class ac_db(device):
  def __init__ (self, host, mac):
    device.__init__(self, host, mac)
    self.type = "Ac Danham bush"

  
	
  def check_sensors_raw(self):
    packet = bytearray(16)
    packet[0] = 1
    response = self.send_packet(0x6a, packet)
    err = response[0x22] | (response[0x23] << 8)
    if err == 0:
      data = {}
      aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
      payload = aes.decrypt(bytes(response[0x38:]))
      if type(payload[0x4]) == int:
        data['temperature'] = (payload[0x4] * 10 + payload[0x5]) / 10.0
        data['humidity'] = (payload[0x6] * 10 + payload[0x7]) / 10.0
        data['light'] = payload[0x8]
        data['air_quality'] = payload[0x0a]
        data['noise'] = payload[0xc]
      else:
        data['temperature'] = (ord(payload[0x4]) * 10 + ord(payload[0x5])) / 10.0
        data['humidity'] = (ord(payload[0x6]) * 10 + ord(payload[0x7])) / 10.0
        data['light'] = ord(payload[0x8])
        data['air_quality'] = ord(payload[0x0a])
        data['noise'] = ord(payload[0xc])
      return data	
	  
  def check_temperature(self):
    packet = bytearray(32)
    packet[0] = 1
    response = self.send_packet(0x6a, packet)
    err = response[0x22] | (response[0x23] << 8)
    if err == 0:
      aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
      payload = aes.decrypt(bytes(response[0x38:]))
      if type(payload[0x4]) == int:
        temp = (payload[0x4] * 10 + payload[0x5]) / 10.0
      else:
        temp = (ord(payload[0x4]) * 10 + ord(payload[0x5])) / 10.0
      return temp
  
  
  ###  UDP checksum fucntion
  def checksum_func(self,data):
	checksum = 0
	data_len = len(data)
	if (data_len%2) == 1:
		data_len += 1
		data += struct.pack('!B', 0)

	for i in range(0, len(data), 2):
		w = (data[i] << 8) + (data[i + 1])
		checksum += w

	checksum = (checksum >> 16) + (checksum & 0xFFFF)
	checksum = ~checksum&0xFFFF
	return checksum
  
  def test(self):
	class FIXATION:
		class VERTICAL:
			#OFF= 0b00000000
			TOP= 0b00000001
			MIDDLE= 0b00000010
			MIDDLE2 = 0b00000011
			BOTTOM= 0b00000100
			SWING= 0b00000110
			AUTO = 0b00000111
			
	class MODE:
		COOLING	=	0b00000010
		DRY		=	0b00000100
		HEATING	=	0b00001000
		AUTO	=	0b00000000
		FAN 	=	0b00001100   
	OFF = 0
	ON = 1
	
  
	#packet = bytearray(32)
	#10111011 00000000 00000110 10000000 00000000 00000000 00001111 00000000 00000001 9 00000001 10 01000111 11 00101000  12 00100000 13 10100000 14 00000000 15 00100000  16 00000000 17 00000000 18 00100000 19 00000000 20 00010000 21 00000000 22 00000101 10010001 10010101

	data = {}
	data['temp'] = 24
	data['fixation_v'] = FIXATION.VERTICAL.AUTO
	data['power'] = ON
	data['mode'] = MODE.HEATING
	data['sleep'] = OFF
 	
	if data['temp'] < 16:
		data['temp'] = 16
	elif data['temp'] > 32:
		data['temp'] = 32
		
	##Temperature is offset by 8
	temperature = data['temp'] -8
	
 	#0b11000111
	byte_10 = temperature << 3 | data['fixation_v']
	print "bla:" +  format(byte_10, '02x')
	 
	payload  = bytearray.fromhex("bb 00 06 80 00 00 0f 00 01 01 9f 22 88 a0 000000000000000000")
	payload[0] = 0xbb
	payload[1] = 0x00
	payload[2] = 0x06
	payload[3] = 0x80
	payload[4] = 0x00
	payload[5] = 0x00
	payload[6] = 0x0f
	payload[7] = 0x00
	payload[8] = 0x01
	payload[9] = 0x01
	payload[10] = temperature << 3 | data['fixation_v']   #1 2 Temprature dunno 6-7:Swing Pos 0 up, 1 middle? 2 down 3hold? 8:Swing. 1 Fixed, 0 Temprature:  8+value
	payload[11] = 0b00101000   
	payload[12] = 0b10100000  # bit 1:  0.5  #bit
	payload[13] = 0b10100000
	payload[14] = 0x00
	payload[15] = data['mode'] << 4 | data['sleep'] << 2 # "mode"  80 heat  ‭1000 0000‬, 20 cooling ‭0010 0000‬  40 dry ‭0100 0000‬  Auto 0000   0000 0100 Sleep
	payload[16] = 0b00000000
	payload[17] = 0x00
	payload[18] = data['power']<<5 # 3 bit on/off
	payload[19] = 0x00
	payload[20] = 0b00010000   #0001 Display on
	payload[21] = 0b00000000  
	payload[22] = 0b00000000 
	
	
	
	# first byte is length, Then placeholder then payload +2 for CRC16	
	request_payload = bytearray(32)
	print "Packet:"+ ''.join(format(x, '02x') for x in request_payload)
	request_payload[0] = len(payload) + 2  ##Length plus of payload plus crc	
	print "Packet:"+ ''.join(format(x, '02x') for x in request_payload)
	request_payload[2:len(payload)+2] = payload  ##Add the Payload
	
	print "Packet:"+ ''.join(format(x, '02x') for x in request_payload)
	
	# append CRC
	crc = self.checksum_func(payload)
	print "Checksum:"+format(crc,'02x')
	request_payload[len(payload)+1] = ((crc >> 8) & 0xFF)
	request_payload[len(payload)+2] = crc & 0xFF
	
	
	print len(request_payload)
	print "Packet:"+ ''.join(format(x, '02x') for x in request_payload)
	
	response = self.send_packet(0x6a, request_payload)
	 
	
	#response = bytearray.fromhex("5aa5aa555aa5aa55000000000000000000000000000000000000000000000000e5d900002a4e6a001781af41a70d43b401000000c4c20000735660cad8ada342d7a4e93e38ba7c6d29cbfc4f2ddfdec75720b2d04da25894")
	print "Resposnse:" + ''.join(format(x, '02x') for x in response)

	err = response[0x22] | (response[0x23] << 8)
	if err == 0:
		aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))		
		response_payload = aes.decrypt(bytes(response[0x38:]))
	
		print "Payload:" + response_payload+"\n"
    	print "Payload: Nice:" + ''.join(x.encode('hex') for x in response_payload )

	return "done"

	
# For legay compatibility - don't use this
class rm2(rm):
  def __init__ (self):
    device.__init__(self, None, None)

  def discover(self):
    dev = discover()
    self.host = dev.host
    self.mac = dev.mac
