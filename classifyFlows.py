
# Phase3 classifyFlows.py
# by Team 18 (Cole Winsor & Daniel McDonough)
# This script monitors packets and produces log flows once a packet burst has concluded



import pyshark
import time
import sys
import sklearn
import numpy
import joblib
import time
import statistics
from sklearn.svm import SVC



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
				
	def classify_str(self, classifier):
		return_str = ""
		first = True
		for fs in self.flows:
			if not first:
				return_str += '\n'
			first = False
			return_str += self.int_to_time_str(int(self.last_time - self.start_time)) + " " + str(fs) + " " + fs.classify(classifier, len(self.flows))
		return return_str

	def int_to_time_str(self, time):
		seconds = time % 60
		minutes = (time // 60) % 60
		hours = (time // 3600) % 100
		return '%02d:%02d:%02d' % (hours, minutes, seconds)

	def get_vectors(self):
		return [flow.get_vector() + [len(self.flows)] for flow in self.flows]

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
		return "%15s %15s %7s %7s %3s" % (str(self.src_a), str(self.dst_a), str(self.src_p), str(self.dst_p), str(self.protocol))


class FlowStats:
	def __init__(self, length, flow):
		self.flow = flow
		self.all_flows = [flow]
		self.sent_length = [length]
		self.recieved_length = []
		self.sent_p = 1
		self.recieved_p = 0
		self.sent_b = length
		self.recieved_b = 0
		self.sent_std = 0
		self.recieved_std = 0
	
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
			self.all_flows += [flow]
			self.sent_length += [length]
			
		else:
			self.recieved_p += 1
			self.recieved_b += length
			self.all_flows += [flow]
			self.recieved_length += [length]

		return True
			
	# returns true if the given flow is in the sending direction
	# returns false otherwise	
	def is_sending(self, flow):
		# may want to expand this to be every aspect pf the flow, but as it currently is used, this should be fine
		if self.flow.src_a == flow.src_a:
			return True
		return False

	def get_std(self, length_array):
		if len(length_array) > 1:
			return statistics.stdev(length_array)
		return 0


	def get_vector(self):
		return [self.sent_p, self.sent_b, self.recieved_p, self.recieved_b, self.get_std(self.sent_length), self.get_std(self.recieved_length)] # TODO decide the best features to use
	
	def classify(self, classifier, num_flows):
		return classifier.classify([self.get_vector() + [num_flows]])[0] 

class CaptureClassifier:

	def __init__(self, file, printing=True):
		self.bursts = []
		self.start_time = time.time()
		
		print("Parsing Capture: " + str(file))
		
		file = open(file)
		capture = pyshark.FileCapture(file, display_filter='tcp or udp and not arp')
		for _, packet in enumerate(capture):
			self.packet_callback(packet)
		
		capture.close()

		print("Finished Parsing. # bursts: " + str(len(self.bursts)))

	def get_io_vectors(self, app):
		training_in = [] 
		for burst in self.bursts:
			complete_vectors = [vector for vector in burst.get_vectors()]
			training_in += complete_vectors
		training_out = [app] * len(training_in)
		return training_in, training_out
		

	def packet_callback(self, pkt):
		current_time = self.time_to_int(pkt.sniff_time)
		length = int(pkt.captured_length)
		protocol = pkt.transport_layer
		if protocol == 'TCP' or protocol == 'UDP':
			source_ip = pkt.ip.src
			source_port = pkt[pkt.transport_layer].srcport
			destination_ip = pkt.ip.dst
			destination_port = pkt[pkt.transport_layer].dstport

			self.add_flow(current_time, length, Flow(protocol, source_ip, source_port, destination_ip, destination_port))
	
	def time_to_int(self, time):
		return time.second + 60 * time.minute + 3600 * time.hour + (time.microsecond / 1000000)

	def add_flow(self, time, length, flow):
		if len(self.bursts) == 0:
			new_burst = Burst(time)
			self.bursts.append(new_burst)
		if time - self.bursts[-1].last_time > 1:
			new_burst = Burst(time)
			self.bursts.append(new_burst)
		self.bursts[-1].add_flow(time, length, flow)

	
	def print_bursts(self):
		for burst in self.bursts:
			print(str(burst))
	
	def print_classified_bursts(self):
		classifier = Classifier()
		i = 1
		for burst in self.bursts:
			print("\nBurst: "+str(i))
			i+=1
			print(burst.classify_str(classifier))

class LiveClassifier:
    
	def __init__(self):
		self.bursts = []
		self.start_time = time.time()
		self.classifier = Classifier()
		# starts the packet capturing, only looks at tcp and udp packets
		capture = pyshark.LiveCapture(interface='eth1', bpf_filter='tcp or udp and not arp')
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
			new_burst = Burst(time, start_time=int(self.start_time))
			self.bursts.append(new_burst)
		if time - self.bursts[-1].last_time > 1:
			print(self.bursts[-1].classify_str(self.classifier)) # TODO remove len(bursts from the training)
			new_burst = Burst(time, start_time=int(self.start_time))
			self.bursts.append(new_burst)
		self.bursts[-1].add_flow(time, length, flow)

class Classifier:
	
	def __init__(self):
		self.path = 'classifier_save.pkl'
		self.classifier = joblib.load(self.path)
		print("Loading Classifier")

	def train(self, vector_in, vector_out):
		print("Trining Classifier")
		X = numpy.array(vector_in)
		y = numpy.array(vector_out)
		self.classifier.fit(X, y)
		print("Finished Training")

	def save(self):
		joblib.dump(self.classifier, self.path)
		print("Saving Classifier")

	def classify(self, vector_in):
		print("Classifying...")
		X = numpy.array(vector_in)
		return self.classifier.predict(X)


#Global state
#probably just move this to another class at some point


def main():
	input = sys.argv
	app_list = ["browser", "youtube", "weather", "news", "ninja"]
	capture_range = [1, 36]
	analysis_range = [36, 51]
	if len(input) < 2:
		print("Capture file is required")
	if len(input) == 2:
		if input[1] == '-t':
			print("Classifier Training")
			v_in = []
			v_out = []
			data_path = "./data/"
			for app in app_list:
				app_path = data_path + app + "/"
				for index in range(capture_range[0], capture_range[1]):
					capture_path = app_path + "test" + str(index) + ".pcap"
					capture = CaptureClassifier(capture_path, printing=False)
					v_io = capture.get_io_vectors(app)
					v_in += v_io[0]
					v_out += v_io[1]
			classifier = Classifier()
			classifier.train(v_in, v_out)
			classifier.save()
		elif input[1] == '-b':
			print("Analyzing Classifier")
			v_in = []
			v_out = []
			data_path = "./data/"
			for app in app_list:
				app_path = data_path + app + "/"
				for index in range(analysis_range[0], analysis_range[1]):
					capture_path = app_path + "test" + str(index) + ".pcap"
					capture = CaptureClassifier(capture_path, printing=False)
					v_io = capture.get_io_vectors(app)
					v_in += v_io[0]
					v_out += v_io[1]
			classifier = Classifier()
			output = classifier.classify(v_in)
			correct = 0
			incorrect = 0
			for i in range(0, len(output)):
				if v_out[i] == output[i]:
					correct += 1
				else:
					incorrect += 1
			print("Correct: " + str(correct / (correct + incorrect)) + " Incorrect: " + str(incorrect / (correct + incorrect)))
		elif input[1] == '-c':
			print("Create New Classifier")
			classifier = SVC(class_weight='balanced')
			joblib.dump(classifier, "classifier_save.pkl")
		elif input[1] == '-l':
			print("Live Classification")
			capture = LiveClassifier()
		else:
			print("Capture Classification")
			capture = CaptureClassifier(input[1])
			capture.print_classified_bursts()
	if len(input) > 2:
		print("Too many arguments")

if __name__ == "__main__":
	main()



