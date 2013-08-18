#!/usr/bin/env python
 
import socket
import sys
import struct
import json

HOST = 'localhost'
PORT = 9099

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# Token (BSTO)
token = 0x4f545342

# Packet types
packet_type_enum = dict(
    none = 0,
    ack = 2,
    nack = 4,
    ping = 9,
    pong = 10,
    json = 20,
    error = 254,
)
packet_type_lookup = {y:x for x,y in packet_type_enum.iteritems()}

type_none = 0
type_ack = 2
type_nack = 4
type_ping = 9
type_pong = 10
type_json = 20
type_error = 254

def pack(data):
    data = list(data)
    length = len(data)
    args = [token, sequence, packet_type_enum['json'], length]+ data
    packet = struct.pack('>LHHI%dc' % len(data), *args)
    return packet

def unpack(data):
    json_data = None
    token, sequence, packet_type, length = struct.unpack('>LHHI', data[:12])
    if packet_type == type_json:
        json_data = struct.unpack('>%dc' % length, data[12:])
    return {
        'token': token,
        'sequence': sequence,
        'packet_type': packet_type_lookup[packet_type],
        'length': length,
        'json': json_data,
    }
        
    
data = {
    'attributes': {
        'username': sys.argv[1],
        'password': sys.argv[2],
    },
    'command': 'register',
    'from': '',
    'id': '50Bp6LxQFBD4ZFVq40F3w0fFlJbxUZ4D',
    'timestamp': '20130120T22:23:47',
    'to': '',
    'type': 'client',
}
json_data = list(json.dumps(data))

sequence = 15

# Header + JSON body:
# unsigned 32 token
# unsigned 16 sequence
# unsigned 16 type
# unsigned 32 length
# char * json 

#length = len(json_data)
#args = [token, sequence, type_json, length]+ json_data
#packet = struct.pack('>LHHI%dc' % len(json_data), *args)
#s.send(packet)
#fh = open('sent.packet', 'w')
#fh.write(packet)
#fh.close()
packet = pack(json.dumps(data))
s.send(packet)

# Expect an ACK packet back
response = s.recv(1024)
fh = open('recv.packet', 'w')
fh.write(response)
fh.close()
print '%r' % unpack(response)

# okay... never received a response to say whether authentication was successful
while 1:
    response = s.recv(1024)
    if response:
        print "Received a response"
s.close()
