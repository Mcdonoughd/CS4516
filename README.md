###CS4516 Project

##Phase 3 - classifyFlows.py

#Team 18 (Cole Winsor & Daniel McDonough)

#Requirements

1. Python 3.6
2. Memory was increased to be 1GB
3. Below are the Required packages to be installed:

  joblib==0.13.2

  Logbook==1.4.3

  lxml==4.3.3

  numpy==1.16.2

  py==1.8.0

  pyshark==0.4.2.2

  scikit-learn==0.20.3

  scipy==1.2.1

  sklearn==0.0


This can be done by
`sudo python3.6 -m pip install sklearn`


#How to Run
Once the Required packages are installed, you can run the code by
`sudo python3.6 classifyFlows.py [option]`


Options are as follows (you may only do one at a time):
1. -t: This tells the script to read the saved classifier file and run the training data
2. -c Produces a saved classifier file 'classifier_save.pkl' in the root directory
3. 'pcap file' Runs a pcap file and determines what

# Classification Limitations
1. We only analyze 5 dimensions: number and sizes of packets sent and received, and the Standard Deviation of the the size of the sent packets.
2. Because of the way Fruit ninja sends packets and its large diversity of packets, this classifier tends to mistake other packets for it.


#How it works
1. Collection of data
All data collected was collected using tshark. A pcap trace started from when the app first launched, and there was a significant pause between bursts, a human intervened to end the pcap trace.

Notes:
- Location was rejected when asked
- Between each test, all background apps were cleared
- News size varied depending on if the highlighted new was video or text
- Fruit Ninja tended to have large ranges of packet sizes



2. Flow
A flow as we defined it, is the set of all data that flow within the single packet burst. Here we analyze a flow as the number and sizes of packets sent and received as well as the Standard Deviation of the the size of the sent packets.
3. Cleaning Data
When reading the pcap trace file, the program only reads the UDP and TCP protocol packets.
