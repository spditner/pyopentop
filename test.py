#!/usr/bin/env python
 
import socket
import sys
import struct
import json
import datetime

HOST = 'localhost'
PORT = 9099

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# Token (BSTO)
token = 0x4f545342
sequence = 0 

test_sdp = """v=0
o=- 3206655683 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE audio
m=audio 1 RTP/SAVPF 9 0 8 126 
c=IN IP4 0.0.0.0
a=rtcp:1 IN IP4 0.0.0.0
a=ice-ufrag:FAXdCWAGMBXKHbdD
a=ice-pwd:9dUaqGYFW2rYnLCaGP5bEaEa
a=sendrecv
a=mid:audio
a=rtcp-mux
a=crypto:0 AES_CM_128_HMAC_SHA1_32 inline:c2tBZFVmR1U0WkhETEQ5OXA4VVViZDhCd3VmRDJH
a=rtpmap:9 g722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:126 telephone-event/8000
a=ssrc:3192024668 cname:y48aubLGfmT0Fl+0
a=ssrc:3192024668 mslabel:kmGQZMjt0XfTlkH7IWMqPguDlCsykGUEMpF8
a=ssrc:3192024668 label:kmGQZMjt0XfTlkH7IWMqPguDlCsykGUEMpF800
a=candidate:2756956640 1 udp 2130706431 192.168.1.254 58888 typ host generation 0
a=candidate:2756956640 2 udp 2130706431 192.168.1.254 58888 typ host generation 0"""

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

def timestamp():
    return datetime.datetime.utcnow().strftime('%Y%m%dT%H:%M:%S')

def pack(data):
# Header + JSON body:
# unsigned 32 token
# unsigned 16 sequence
# unsigned 16 type
# unsigned 32 length
# char * json 

    print "Packing:\n%r" % data
    global sequence
    sequence = sequence+1
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
        
    
# Log in
if True:
    data = {
        'attributes': {
            'username': sys.argv[1],
            'password': sys.argv[2],
        },
        'command': 'register',
        'from': '',
        'id': '50Bp6LxQFBD4ZFVq40F3w0fFlJbxUZ4D',
        'timestamp': timestamp(),
        'to': '',
        'type': 'client',
    }
    json_data = list(json.dumps(data))

    packet = pack(json.dumps(data))
    s.send(packet)
    fh = open("send.packet", "w")
    fh.write(packet)
    fh.close()

    # Expect an ACK packet back
    response = s.recv(1024)
    print '%r' % unpack(response)
    fh = open('recv.packet', 'w')
    fh.write(response)
    fh.close()

# Attempt to announce our presence?
if False:
    packet = pack(json.dumps(
        {
            'attributes': {
                'username': sys.argv[1],
            },
            "type":"presence",
            "command":"push",
            "id":"50Bp6LxQFBD4ZFVq40F3w0fFlJbxUZ4D",
            "timestamp":timestamp(),
            "to":"spditner@opentop.org",
            "from":"nlrentid@opentop.org",
            "attributes": {
                "status":"away",
                "message":"Out to lunch..."
            }
        }
    ))
    s.send(packet)
    response = s.recv(1024)
    print '%r' % unpack(response)

# Attempt to subscribe to someone's presence
if False:
    packet = pack(json.dumps(
    {
        'attributes': {
            'username': sys.argv[1],
        },
        "type":"presence",
        "command":"subscribe",
        "id":"50Bp6LxQFBD4ZFVq40F3w0fFlJbxUZ4D",
        "timestamp":timestamp(),
        "to":"spditner@opentop.org",
        "from":"nlrentid@opentop.org",
    }
    ))
    s.send(packet)
    response = s.recv(1024)
    print '%r' % unpack(response)

# Attempt to call someone
if True:
    packet = pack(json.dumps(
        {
            "type":  "call",
            "command": "offer",
            "id": "50Bp6LxQFBD4ZFVq40F3w0fFlJbxUZ4D",
            "timestamp": timestamp(),
            "to": "testcall@opentop.org",
            "from" : "nlrentid@opentop.org",
            "attributes":  {
                'username': sys.argv[1],
                "sdp ": test_sdp,
            }
        }
    ))
    s.send(packet)
    response = s.recv(1024)
    print '%r' % unpack(response)

# okay... never received a response to say whether authentication was successful

# Logout
if False:
    packet = pack(json.dumps({
        "type": "client",
        "command": "unregister",
        "id": "50Bp6LxQFBD4ZFVq40F3w0fFlJbxUZ4D",
        "timestamp": timestamp(),
        "to": "",
        "from": "",
        "attributes": {
            "username": "nlrentid@opentop.org",
        },
    }))
    s.send(packet)
    response = s.recv(1024)
    print '%r' % unpack(response)

response = s.recv(1024)
print '%r' % unpack(response)

s.close()
