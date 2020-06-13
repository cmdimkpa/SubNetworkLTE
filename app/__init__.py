#============== Python3 Flask Model of LTE Sub Network ==============

#   Version: 1.00
#   Author: Monty Dimkpa

#====================================================================


#-------------- Importing required Python libraries --------------

from flask import Flask, request
from flask_cors import CORS
import sys
import os
import pickle
from random import random
import datetime
from hashlib import md5

app = Flask(__name__)
CORS(app)

#-------------- Network Initialization Parameters --------------

server_host = "localhost"
server_port = 5000

HOST_NETWORK = {} # In-memory Network
NETWORK_HOME = "/home/network"
slash = "/"

#-------------- LTE Network Constants ------

# Transmission Bandwidth = 20MHz
# Number of RBs = 100 blocks
# RB Frequency = 180KHz
# 180 bits per block each TTI (1ms) x 100 blocks = 18000 bits per TTI (1ms)
# Number of sub-carriers = 12
MAC_packet_size = int(18000/12) # max bits per TTI divided by number of sub-carriers
transmission_bit_limit_per_tti = 18000
BER_baseline = 0.2 # Network Bit Error Rate baseline
retransmission_limit = 6 # Network packet retransmission limit
packet_duplication = 4 # Network packet duplication
effective_delay_budget = 300 # effective packet delay budget of 300ms for LTE
min_IP_packet_size = 500
max_IP_packet_size = 2000

#-------------- Base Classes --------------

def Path(path_array):
    global HOST_NETWORK
    location = "";
    for level in path_array:
        location+="%s%s" % (slash, level);
    if (location not in HOST_NETWORK):
        HOST_NETWORK[location] = None;
    return location

def now(): return datetime.datetime.today()

def ms_elapsed(t): return int(1000*(now() - t).total_seconds())

def Id():
    hasher = md5(); hasher.update(str(now()).encode())
    return hasher.hexdigest()

def load_error_multiplier():
    # higher packet delays in the PUCCH signal higher cell loads and a higher BER
    try:
        QueuedMACPackets = [pickle.loads(loggable) for loggable in PhysicalUplinkControlChannel.read_netbuffer("QueuedMACPackets")]
        n_packets = len(QueuedMACPackets)
        total_delay = 0
        for packet in QueuedMACPackets:
            total_delay += packet.header[0]
        avg_delay = total_delay/n_packets
        return avg_delay/effective_delay_budget
    except Exception as e:
        print("Error @ load_multiplier : %s" % str(e))
        return 1

def is_transcoding_error(noise_level):
    # cell loading increases the bit error rate
    return noise_level < BER_baseline*load_error_multiplier()

class IP_Packet:
    # This class creates an IP Packet
    def __init__(self, sessionId, size, source, time):
        self.sessionId = sessionId
        self.header = [size, source, time, 0, 0]
        self.payload_bits = "".join([str(int(random()*2)) for i in range(size)]).encode()  # initial random bits in IP packet
    def loggable(self):
        return pickle.dumps(self)

def MAC2IPSession(MAC_packet):
    # this function converts a MAC packet back to an IP session for retransmission
    session_time = now()
    IP_packet = IP_Packet(MAC_packet.sessionId, MAC_packet.header[8], MAC_packet.header[1], session_time)
    IP_packet.header[3] += MAC_packet.header[0]  # add retransmission delay
    IP_packet.header[4] = MAC_packet.header[4]  # update retransmissions
    IP_packet.payload_bits = MAC_packet.header[3]
    return [MAC_packet.header[1], session_time, IP_packet.sessionId, 1, duplicate([IP_packet.loggable()], packet_duplication)]

class MAC_Packet:
    # this class creates a MAC packet
    def __init__(self, sessionId, trans_bits, source, delay, source_bits, retransmissions, packetId, packet_index, n_mac_packets, size):
        self.sessionId = sessionId
        self.header = [delay, source, now(), source_bits, retransmissions, packetId, packet_index, n_mac_packets, size]
        self.payload_bits = trans_bits
    def loggable(self):
        return pickle.dumps(self)

def transcode_bits(bits, plan):
    # this is the bit transcoding function that copies bits from an IP packet stream into a new MAC packet
    noise_level = random()*random()  # fixed random noise level during transcoding
    field = [x for x in bits.decode()]
    bands = []
    for size in plan:
        source = []; trans = []
        for i in range(size):
            bit = field.pop(0) # preserve bit order
            source.append(bit)
            # bit error will occur if cell load increases baseline BER above current noise level
            if is_transcoding_error(noise_level):
                trans.append(str(abs(int(float(bit)-1))))
            else:
                trans.append(bit)
        bands.append(["".join(source).encode(), "".join(trans).encode()])
    return bands

def transcoding_plan(x, b):
    # function for creating a plan to split a bit stream into smaller streams that are not greater than the MAC packet size
    divs = x // b
    rem = x % b
    if divs:
        if rem:
            return [b for i in range(divs)]+[rem]
        else:
            return [b for i in range(divs)]
    else:
        return [x]

def packet_size():
    # returns an initial random size for an IP packet
    return int(min_IP_packet_size + random()*(max_IP_packet_size - min_IP_packet_size))

def duplicate(array, n):
    # function to duplicate the IP packets n times given the original array
    container = []
    for i in range(n):
        container+=array
    return container

def UESession(ip_address, n_packets):
    # authenticates a UE and creates a session to handle the IP packet uplink
    sessionId = Id()
    session_time = now()
    return [ip_address, session_time, sessionId, n_packets, duplicate([IP_Packet(sessionId, packet_size(), ip_address, session_time).loggable() for i in range(n_packets)], packet_duplication)]

class NetworkDataManager:
    global HOST_NETWORK
    def __init__(self, netbuffer_host_dir):
        self.netbuffer_path = Path([NETWORK_HOME, netbuffer_host_dir]);
        self.netbuffers = {}
    def register_new_netbuffer(self, netbuffer_type):
        self.netbuffers[netbuffer_type] = Path(self.netbuffer_path+["%s.netbuffer" % netbuffer_type])
    def write_netbuffer(self, netbuffer_type, data):
        if netbuffer_type not in self.netbuffers:
            self.register_new_netbuffer(netbuffer_type)
        HOST_NETWORK[self.netbuffers[netbuffer_type]] = pickle.dumps(data);
        return data
    def read_netbuffer(self, netbuffer_type):
        try:
            if netbuffer_type in self.netbuffers:
                data = pickle.loads(HOST_NETWORK[self.netbuffers[netbuffer_type]])
                return data
            else:
                return None
        except:
            return None

def log(sessionId, request, response):
    # this is the logging function that produces color-coded records of events that occur in the network
    def format():
        colorMap = {
            "IP_PACKETS_RECEIVED": "yellow",
            "MAC_PACKETS_MODULATED": "cyan",
            "RETRANSMITTED_PACKET": "orange",
            "QUEUED_PACKET": "green",
            "REJECTED_PACKET": "red",
            "SORTED_PACKET": "pink"
        }
        return str(now()), sessionId, colorMap[request], request, response
    Log = NetLog.read_netbuffer("log")
    if Log:
        Log.append(format())
    else:
        Log = [format()]
    NetLog.write_netbuffer("log", Log)
    return None

#-------------- Component Data Models --------------

AirInterface = NetworkDataManager("AirInterface") # Handles initial packets entering the network
PhysicalUplinkControlChannel = NetworkDataManager("PhysicalUplinkControlChannel") # Modulates IP packets to MAC packets
MAC = NetworkDataManager("MAC") # validates packets and handles retransmissions or queueing of verified packets
Scheduler = NetworkDataManager("Scheduler") # sorts verified packets and schedules transmission of packets
Transmission = NetworkDataManager("Transmission") # transmits and terminates scheduled packets
NetLog = NetworkDataManager("NetLog") # records events in the network

#-------------- Network Endpoints --------------

# simulation agent firing mechanism for returning activity logs
@app.route("/SubNetworkLTE/NetLog")
def ShowActivity():
    Log = NetLog.read_netbuffer("log")
    if Log:
        html = '<html><body bgcolor="black"><div style="color: white; font-family: consolas; font-size:12;">%s</div></body></html>'
        spool = ""; count = -1
        for log in Log[::-1]:
            count+=1
            spool += '<p><b>%s --> </b>[%s] <span style="color: %s;">[%s]</span> [%s]' % log + ' (#%s)</p>' % str(len(Log) - count)
        return html % spool
    else:
        return "%s: %s" % (404, "No activity logs found")

# simulation agent firing mechanism for sorting verified packets
@app.route("/SubNetworkLTE/Scheduler/Sorter")
def SortPackets():
    try:
        TransmissionQueue = MAC.read_netbuffer("TransmissionQueue")
        packet = pickle.loads(TransmissionQueue.pop())  # release a MAC packet
        MAC.write_netbuffer("TransmissionQueue", TransmissionQueue)
        sessionId = packet.sessionId
        SortedPackets = Scheduler.read_netbuffer("SortedPackets")
        if SortedPackets:
            if sessionId in SortedPackets:
                SortedPackets[sessionId].append(packet.loggable())
            else:
                SortedPackets[sessionId] = [packet.loggable()]
        else:
            SortedPackets = {sessionId: [packet.loggable()]}
        Scheduler.write_netbuffer("SortedPackets", SortedPackets)
        log(sessionId, "SORTED_PACKET", "1 packet with id: %s was sorted (%s bits)" % (packet.header[5], packet.header[8]))
        return "%s: %s" % (201, "Packet was sorted (%s bits)" % packet.header[8])
    except Exception as e:
        print("Error @ sorter : %s" % str(e))
        return "%s: %s" % (404, "No packet found")

# simulation agent firing mechanism for validating packet integrity
@app.route("/SubNetworkLTE/MAC/Profiler")
def ProfilePackets():
    def retransmit(packet):
        # check if retransmission_limit reached
        if packet.header[4] + 1 > retransmission_limit:
            # reject this MAC packet
            RejectedPackets = MAC.read_netbuffer("RejectedPackets")
            if RejectedPackets:
                RejectedPackets.append(packet.loggable())
            else:
                RejectedPackets = [packet.loggable()]
            MAC.write_netbuffer("RejectedPackets", RejectedPackets)
            log(packet.sessionId, "REJECTED_PACKET", "1 packet with id: %s was rejected (%s bits)" % (packet.header[5], packet.header[8]))
            return "%s: %s" % (204, "Packet was rejected (%s bits)" % packet.header[8])
        else:
            packet.header[4]+=1
            retransmitted_session = MAC2IPSession(packet) # convert MAC packet back to IP session
            UERegister = AirInterface.read_netbuffer("UERegister")
            if UERegister:
                UERegister.append(retransmitted_session)  # lower priority for unvalidated retransmitted packets
            else:
                UERegister = [retransmitted_session]
            AirInterface.write_netbuffer("UERegister", UERegister) # retransmit IP session
            log(packet.sessionId, "RETRANSMITTED_PACKET", "1 packet with id: %s was retransmitted (%s bits)" % (packet.header[5], packet.header[8]))
            return "%s: %s" % (200, "Packet was retransmitted (%s bits)" % packet.header[8])
    def queue(packet):
        TransmissionQueue = MAC.read_netbuffer("TransmissionQueue")
        if TransmissionQueue:
            TransmissionQueue.insert(0, packet.loggable())  # FIFO
        else:
            TransmissionQueue = [packet.loggable()]
        MAC.write_netbuffer("TransmissionQueue", TransmissionQueue) # queue this transmittable MAC packet
        log(packet.sessionId, "QUEUED_PACKET", "1 packet with id: %s was queued (%s bits)" % (packet.header[5], packet.header[8]))
        return "%s: %s" % (201, "Packet was queued (%s bits)" % packet.header[8])
    packet = None
    try:
        QueuedMACPackets = PhysicalUplinkControlChannel.read_netbuffer("QueuedMACPackets")
        packet = pickle.loads(QueuedMACPackets.pop()) # release a MAC packet
        PhysicalUplinkControlChannel.write_netbuffer("QueuedMACPackets", QueuedMACPackets)
        # test MAC packet for errors, handle contextually
        if packet.payload_bits == packet.header[3]:
            return queue(packet)
        else:
            return retransmit(packet)
    except Exception as e:
        print("Error @ profiler : %s" % str(e))
        return "%s: %s" % (404, "No packet found")

# simulation agent firing mechanism for transcoding IP packets to MAC packets
@app.route("/SubNetworkLTE/PhysicalUplinkControlChannel/Modulation")
def ModulatePackets():
    session = None
    UERegister = AirInterface.read_netbuffer("UERegister")
    if UERegister:
        session = UERegister.pop()
        AirInterface.write_netbuffer("UERegister", UERegister)
        ip_address, session_time, sessionId, n_packets, ip_packets_loggable = session
        ip_packets = [pickle.loads(log) for log in ip_packets_loggable]
        # Packet Modulation
        delay = ms_elapsed(session_time); modulated = 0
        for packet in ip_packets:
            delay+=packet.header[3]  # add retransmission delay
            mod_started = now()
            MAC_packets = []
            packetId = Id()
            field = transcode_bits(packet.payload_bits, transcoding_plan(packet.header[0], MAC_packet_size))
            packet_index = -1
            for band in field:
                packet_index+=1
                source_bits, trans_bits = band
                mod_delay = ms_elapsed(mod_started); delay+=mod_delay # add modulation delay
                # FIFO Queue, preserve retransmissions
                MAC_packets.insert(0, MAC_Packet(sessionId, trans_bits, ip_address, delay, source_bits, packet.header[4], packetId, packet_index, len(field), len(trans_bits)).loggable())
            modulated+=len(MAC_packets)
            QueuedMACPackets = PhysicalUplinkControlChannel.read_netbuffer("QueuedMACPackets")
            if QueuedMACPackets:
                QueuedMACPackets = MAC_packets + QueuedMACPackets # ensure FIFO
            else:
                QueuedMACPackets = MAC_packets
            PhysicalUplinkControlChannel.write_netbuffer("QueuedMACPackets", QueuedMACPackets)
            log(sessionId, "MAC_PACKETS_MODULATED", "%s MAC packets from session %s delayed %sms" % (len(MAC_packets), sessionId, mod_delay))
        return "%s: %s" % (200, "Successfully modulated %s packets" % modulated)
    else:
        return "%s: %s" % (404, "No session found")

# simulation agent firing mechanism for authenticating UE sessions and receiving IP packets
@app.route("/SubNetworkLTE/AirInterface/UERegistration/<path:n_packets>")
def UERegistration(n_packets):
    ip_address = request.remote_addr
    try:
        session = UESession(ip_address, int(n_packets))
    except Exception as e:
        print("Error @ create_session : %s" % str(e))
        return "%s: %s" % (400, "Error creating session: packet_size not specified")
    UERegister = AirInterface.read_netbuffer("UERegister")
    if UERegister:
        UERegister.insert(0, session)  #FIFO Queue
    else:
        UERegister = [session]
    AirInterface.write_netbuffer("UERegister", UERegister)
    log(session[2], "IP_PACKETS_RECEIVED", "UE at %s sent %s IP packets of %s bits" % (ip_address, n_packets, sum([pickle.loads(loggable).header[0] for loggable in session[4]])))
    return "%s: %s" % (200, "Successfully registered %s packets" % n_packets)

if __name__ == "__main__":
    app.run(host=server_host, port=server_port, threaded=True)
