#Classify Flows by Daniel McDonough and Cole Winsor

import sys, os


#Throws a commandline error and ends program
def throwError():
    print('classifyFlows.py <inputfile> <outputfile>')
    sys.exit()

#main function given all args but the name of the file itself
def main(argv):
    inputfile = ''
    outputfile = ''
    print(argv)

    #check correct number fo args
    if len(argv) < 2 or len(argv) >= 3:
        throwError()

    else:
        #check if files exists
        for arg in argv:
            exists = os.path.isfile(arg)
            if not exists:
                throwError()

    print('Input file is ', argv[0])
    print('Output file is ', argv[1])







if __name__ == "__main__":
   main(sys.argv[1:])