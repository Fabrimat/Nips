#!/usr/bin/env python
import os
import time
from subprocess import Popen
import socket
import subprocess
import sys
from datetime import datetime
import logging
import functionscanner

# Clear the screen
subprocess.call('clear', shell=True)

# Console colors
W = '\033[0m'    # white (normal)
R = '\033[31m'   # red
G = '\033[32m'   # green
O = '\033[33m'   # orange
B = '\033[34m'   # blue
P = '\033[35m'   # purple
C = '\033[36m'   # cyan
GR = '\033[37m'  # gray
T = '\033[93m'   # tan



def ip_scanner():
try:

    #Presentation
    print ("Ip Scanner v0.1")
    print ("... type enter to continue ")
    raw_input()

    #Ask for inputs and define variables
    str1=raw_input("Enter the ip range ( ex: 192.168.0 ) - ")
    port=80
    port=input("Enter the port ( default: 80 ) - ")
    showerr=raw_input("print (only the active ips? (y/n) - ")
    devnull = open(os.devnull, 'wb')
    #outlog=raw_input("Save the outputs into a log file? (y/n) - ")

    #starttime = datetime.now()

    #if outlog == "y":
    #    logfilename=raw_input("Type the name of the log file ( ex: scanlog ) - ")
    #    logging.basicConfig(level=logging.DEBUG, filename=(logfilename,starttime), filemode="a+",
    #                    format="%(asctime)-15s %(levelname)-8s %(message)s")

    print ("scanning ip range ",str1)

    if str1 == "" or type(port) != int:
     print ("-=" * 21)
     print ("Please check your inputs and try again...")
     print ("-=" * 21)
     sys.exit()

     #Information variables
    p = [] # ip -> process
    act = 0
    nrp = 0
    err = 0
    opn = 0
    clsd = 0

    # Check what time the scan started
    t1 = datetime.now()

    print ("")
    print (">Please wait, pinging remote ips.")
    print ("")
    #Start pinging and scanning
    for n in range(1,255): # start ping processes
        ip = str1+".%d" % n
        p.append((ip, Popen(['ping', '-c', '3', ip], stdout=devnull)))

    #print ("=-" * 30)
    print (">Starting port scan.")
    #print ("=-" * 30)
    print ("")

    while p:
        for i, (ip, proc) in enumerate(p[:]):
            if proc.poll() is not None: # ping finished
                p.remove((ip, proc)) # this makes it O(n**2)
                if proc.returncode == 0:
                    print('%s active' % ip)
                    act = act + 1
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        print ("\tPort {}: Open".format(port))
                        opn = opn + 1
                    else:
                        print ("\tPort {}: Closed".format(port))
                        clsd = clsd + 1

                elif proc.returncode == 2:
                    if showerr == "n":
                        print('%s no response' % ip)
                    nrp=nrp+1
                else:
                    if showerr == "n":
                        print('%s error' % ip)
                    err=err+1
        time.sleep(.04)
    devnull.close()
    #Stop pinging and scanning

#Errors outputs
except KeyboardInterrupt:
    sys.exit("\n You pressed Ctrl+C")

except socket.gaierror:
    sys.exit('\n Hostname could not be resolved. Exiting')

except socket.error:
    sys.exit("\n Couldn't connect to server")

# Checking the time again
t2 = datetime.now()

# Calculates the difference of time, to see how long it took to run the script
total =  t2 - t1

# Printing the information to screen
print ('Scanning Completed in: ', total)
print ("")
print ("-=" * 9)
print ("Network status")
print ("-=" * 9)
print ("Active ips [ ",act," ]")
print ("Error ips [ ",err," ]")
print ("No response [ ",nrp," ]")
print ("Open ports   [ ",opn," ]")
print ("Closed ports [ ",clsd," ]")
print ("")
print ("Good bye!")
