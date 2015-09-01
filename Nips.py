#!/usr/bin/env python2
import os
import time
from subprocess import Popen
import socket
import subprocess
import sys
from datetime import datetime
import logging

#def IpPortScanner(): - Coming soon!

#Define variables
p = [] # ip -> process
act=0
nrp=0
err=0
opn=0
clsd=0
port=0
devnull = open(os.devnull, 'wb')

# Clear the screen
subprocess.call('clear', shell=True)

#Configuring logging
logger = logging.getLogger('LogScanner')
logging.basicConfig(filename='Nips.log',format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',level=logging.DEBUG)

#Presentation
print ("Nips v1.0 - Network Ip Port Scanner")
print ("... type enter to continue ")
raw_input()

logging.info('######### NEW LOG SESSION ########')

#Ask for inputs
iprange=raw_input("Enter the ip range ( ex: 192.168.0 ) - ")
logging.info('IP Range: %s',iprange)
port=input("Enter the port ( ex: 80 ) - ")
logging.info('Port: %s',port)
showerr=raw_input("Print only the active ips? (y/n) - ")
logging.info('Only active ips? %s',showerr)
#socketdeftime=input("Enter the timeout ( ex: 0.5 ) - ")

#A little alert
print("")
print 'The outputs will be saved as "Nips.log".'
time.sleep(0.5)
print ("")

#Checking errors
if iprange == "" or type(port) != int or port == 0 or len(iprange) > 11 or len(iprange) < 5 or iprange.count(".") != 2:
    print ("-=" * 21)
    print ("Please check your inputs and try again...")
    print ("-=" * 21)
    logging.error('Invalid Inputs: %s - %s - %s - %s - %s',iprange,type(port),port,len(iprange),iprange.count("."))
    sys.exit()

try:
    # Check what time the scan started
    t1 = datetime.now()
    #Start pinging and scanning
    print "Scanning ip range ",iprange
    logging.info('Scanning ip range')
    print ("")
    for n in range(1,255): # start ping processes
        ip = iprange+".%d" % n
        p.append((ip, Popen(['ping', '-c', '3', ip], stdout=devnull)))

    print ("Starting port scan. This can be take a while.")
    logging.info('Starting port scan.')
    print ("")

    while p:
        for i, (ip, proc) in enumerate(p[:]):
            if proc.poll() is not None: # ping finished
                p.remove((ip, proc)) # this makes it O(n**2)
                if proc.returncode == 0:
                    print('%s active' % ip)
                    logging.info('%s active',ip)
                    act = act + 1
                    socket.setdefaulttimeout(0.5)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result = sock.connect_ex((ip, port))
                    try:
                        host = socket.gethostbyaddr(ip)
                        print "\tHostname:",host[0]
                        logging.info("Hostname: %s",host[0])
                        logging.info("Alias list: %s",host[1])
                        logging.info("Ip Addresses List: %s",host[2])
                        host = None
                    except socket.error:
                        logging.info("Hostname: Empty.")
                    sock.close()
                    if result == 0:
                        print ("\tPort {}: Open".format(port))
                        logging.info('Port %s: Open',port)
                        opn = opn + 1
                    else:
                        print ("\tPort {}: Closed".format(port))
                        logging.info('Port %s: Closed',port)
                        clsd = clsd + 1
                elif proc.returncode == 2:
                    if showerr == "n":
                        print('%s no response' % ip)
                    logging.info('%s no response',ip)
                    nrp=nrp+1
                else:
                    if showerr == "n":
                        print('%s error' % ip)
                    logging.info('%s error',ip)
                    err=err+1
        time.sleep(.04)
    devnull.close()
    #Stop pinging and scanning

#Errors outputs
except KeyboardInterrupt:
    sys.exit("\n You pressed Ctrl+C")
    logging.info('You pressed Ctrl+C')

#except socket.gaierror:
#    sys.exit('\n Hostname could not be resolved. Exiting')
#    logging.info('Hostname could not be resolved.')

#except socket.error:
#    sys.exit("\n Couldn't connect to server")
#    logging.info("Couldn't connect to server")

# Checking the time again
t2 = datetime.now()

# Calculates the difference of time, to see how long it took to run the script
total =  t2 - t1

#Logging final information
logging.info('Scanning Completed in: %s',total)
logging.info('Active ips: %s',act)
logging.info('Error ips: %s',err)
logging.info('No reponse ips: %s',nrp)
logging.info('Open ports: %s',opn)
logging.info('Closed ports: %s',clsd)

# Printing the information to screen
print 'Scanning Completed in: ', total
print ""
print "-=" * 9
print "Network status"
print "-=" * 9
print "Active ips [ ",act," ]"
print "Error ips [ ",err," ]"
print "No response ips [ ",nrp," ]"
print "Open ports   [ ",opn," ]"
print "Closed ports [ ",clsd," ]"
print ""
print "Good bye!"
