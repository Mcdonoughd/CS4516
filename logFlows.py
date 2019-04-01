import pyshark
import time

class Burst:

	def __init__(self, current_time, start_time=0):
		self.flows = []
		self.last_time = current_time
		self.start_time = start_time
	
	# adds the information from the given flow into the burst
	def add_flow(self, time, length, flow):
		self.last_time = time
		for fs in self.flows:
			if fs.flow == flow:
				fs.add_flow(length, flow)
				return
		new_fs = FlowStats(length, flow)
		self.flows.append(new_fs)
		
	# gets the time of the most recent flow in the burst
	def last_time(self):
		return self.last_time
	
	# creates a human readable representation of the burst
	def __str__(self):
		return_str = ""
		#return_str +=  "----Burst Statistics----\n"
		#return_str += "Numer of flows: " + str(len(self.flows)) + "\n"
		first = True
		for fs in self.flows:
			# takes care of newlines between flows
			if not first:
				return_str += "\n"
			first = False

			return_str += self.int_to_time_str(int(self.last_time - self.start_time)) + " " + str(fs)
		return return_str
				
	def int_to_time_str(self, time):
		seconds = time % 60
		minutes = (time // 60) % 60
		hours = (time // 3600) % 100
		return '%02d:%02d:%02d' % (hours, minutes, seconds)


class Flow:
	def __init__(self, protocol, src_a, src_p, dst_a, dst_p):
		self.protocol = protocol
		self.src_a = src_a
		self.src_p = src_p
		self.dst_a = dst_a
		self.dst_p = dst_p
	
	# returns true if the flows are equivalent and false otherwise
	def __eq__(self, other):
		if self.protocol == other.protocol:
			if self.src_a == other.src_a and self.src_p == other.src_p and self.dst_a == other.dst_a and self.dst_p == other.dst_p:
				return True
			if self.src_a == other.dst_a and self.src_p == other.dst_p and self.dst_a == other.src_a and self.dst_p == other.src_p:
				return True
		return False	

	# returns a human readable representation of the flow
	def __str__(self):
		return "%15s %15s %7s %7s" % (str(self.src_a), str(self.dst_a), str(self.src_p), str(self.dst_p))


class FlowStats:
	def __init__(self, length, flow):
		self.flow = flow
		self.sent_p = 1
		self.recieved_p = 0
		self.sent_b = length
		self.recieved_b = 0
	
	# returns a human readable representation of the flows statistics	
	def __str__(self):
		return "%s %3s %3s %6s %6s" % (str(self.flow), str(self.sent_p), str(self.recieved_p), str(self.sent_b), str(self.recieved_b))

	# updates statistics based on the given flow
	def add_flow(self, length, flow):
		if flow != self.flow:
			return False
		if self.is_sending(flow):
			self.sent_p += 1
			self.sent_b += length
		else:
			self.recieved_p += 1
			self.recieved_b += length
		return True
			
	# returns true if the given flow is in the sending direction
	# returns false otherwise	
	def is_sending(self, flow):
		# may want to expand this to be every aspect pf the flow, but as it currently is used, this should be fine
		if self.flow.src_a == flow.src_a:
			return True
		return False
	

class BurstLogger:

	def __init__(self):
		self.bursts = []
		self.start_time = time.time()
		# starts the packet capturing, only looks at tcp and udp packets
		capture = pyshark.LiveCapture(interface='eth1', bpf_filter='tcp or udp')
		capture.apply_on_packets(self.packet_callback)

	# runs for each packet. Creates flow from packet information
	# and appends the flow to the current burst
	def packet_callback(self, pkt):
		# get the current time
		current_time = time.time()
	
		# get the needed packet information
		length = int(pkt.captured_length)
		protocol = pkt.transport_layer
		source_ip = pkt.ip.src
		source_port = pkt[pkt.transport_layer].srcport
		destination_ip = pkt.ip.dst
		destination_port = pkt[pkt.transport_layer].dstport
	
		#handle adding the packet
		self.add_flow(current_time, length, Flow(protocol, source_ip, source_port, destination_ip, destination_port))

	# appends the given flow to the current burst
	# if the current burst is more than 1 second
	# passed, creates a new burst
	def add_flow(self, time, length, flow):
		if len(self.bursts) == 0:
			new_burst = Burst(time, start_time=self.start_time)
			self.bursts.append(new_burst)
		if time - self.bursts[-1].last_time > 1:
			print(str(self.bursts[-1]))
			new_burst = Burst(time, start_time=self.start_time)
			self.bursts.append(new_burst)
		self.bursts[-1].add_flow(time, length, flow)

# starts the loging process
BurstLogger()

