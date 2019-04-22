# CS4516 Project

## Phase 4 - analyzeFlows.py

### Team 18 (Cole Winsor & Daniel McDonough)

### Requirements

1. Python 3.6
2. Memory was increased to be 1GB
3. Below are the Required packages to be installed:

* joblib==0.13.2 
* Logbook==1.4.3
* lxml==4.3.3
* numpy==1.16.2
* py==1.8.0
* pyshark==0.4.2.2
* scikit-learn==0.20.3
* scipy==1.2.1
* sklearn==0.0


This can be done by
`sudo python3.6 -m pip install PACKAGE_NAME` 


### How to Run
Once the Required packages are installed, you can run the code by
`sudo python3.6 analyzeFlows.py [option]`


Options are as follows (you may only do one at a time):
1. -t: This tells the script to load the saved classifier files and run the training data
2. -c: Produces a new classifier file 'classifier_save.pkl' in the root directory
3. -b: This tells the script to read the saved classifier files and run the testing data
4. 'pcap file': Runs a pcap file to determine bursts and classify flows
5. -l: This tells the program to run a live classification of the program
6. -h: This prints the help function

### Classification Limitations
1. We analyze 7 features: 

- Number of Packets recieved
- Number of packets sent 
- Size of packets sent (bytes) 
- Size of packets received (bytes) 
- Standard deviation of the bytes sent 
- Standard deviation of bytes recieved 
- The number of bursts in the file

2. Fruit Ninja sends a large diversity of packets. Due ot the abnormal amount, and variety of packets on start up, this classifier tends to mistake other packets for it. We tried to account for this by adding the StDv. features but it did not help.
3. Due to the daily variation in data sent from the News app (videos vs text on the homepage), the classifier may incorrectly classify its packets.
4. Limited to 35 pcap traces of training and 15 traces in testing (More data may be needed)
5. SVM may not find a good margin between classes 
6. Human intervention inorder to stop the tracing


### How it works
1. Collection of data

All data collected was collected using tshark. A pcap trace started from when the app first launched, and there was a significant pause between bursts, a human intervened to end the pcap trace.

- Location was rejected when asked
- News app data was collected over a total of two days (both text)
- Weather was opened to Worcester MA
- Between each test, all background apps were cleared
- News size varied depending on if the highlighted new was video or text
- Fruit Ninja tended to have large ranges of packet sizes

2. Flow

A flow as we defined it, is the set of all data that flow within the single packet burst. Here we analyze a flow as the number and sizes of packets sent and received as well as the Standard Deviation of the the size of the sent packets.

3. Cleaning Data

When reading the pcap trace file, the program only reads the UDP and TCP protocol packets.

4. SVM

Flow vectors were classified using SVM 



__Our classifier is roughly 60% accurate.__


