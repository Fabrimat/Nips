#!/usr/bin/env python2
import os
import time
from subprocess import Popen
import socket
import subprocess
import sys
from datetime import datetime
import logging

# Clear the screen
def cls():
    if os.name == "posix":
        subprocess.call('clear', shell=True)
    elif os.name == "nt":
        os.system(['clear','cls'][os.name == 'nt'])

cls()

def ascipres():
    print "\n\n\n"
    print "\tNNNNNNNN        NNNNNNNN  iiii                                      "
    print "\tN:::::::N       N::::::N i::::i                                     "
    print "\tN::::::::N      N::::::N  iiii                                      "
    print "\tN:::::::::N     N::::::N                                            "
    print "\tN::::::::::N    N::::::Niiiiiiippppp   ppppppppp       ssssssssss   "
    print "\tN:::::::::::N   N::::::Ni:::::ip::::ppp:::::::::p    ss::::::::::s  "
    print "\tN:::::::N::::N  N::::::N i::::ip:::::::::::::::::p ss:::::::::::::s "
    print "\tN::::::N N::::N N::::::N i::::ipp::::::ppppp::::::ps::::::ssss:::::s"
    print "\tN::::::N  N::::N:::::::N i::::i p:::::p     p:::::p s:::::s  ssssss "
    print "\tN::::::N   N:::::::::::N i::::i p:::::p     p:::::p   s::::::s      "
    print "\tN::::::N    N::::::::::N i::::i p:::::p     p:::::p      s::::::s   "
    print "\tN::::::N     N:::::::::N i::::i p:::::p    p::::::pssssss   s:::::s "
    print "\tN::::::N      N::::::::Ni::::::ip:::::ppppp:::::::ps:::::ssss::::::s"
    print "\tN::::::N       N:::::::Ni::::::ip::::::::::::::::p s::::::::::::::s "
    print "\tN::::::N        N::::::Ni::::::ip::::::::::::::pp   s:::::::::::ss  "
    print "\tNNNNNNNN         NNNNNNNiiiiiiiip::::::pppppppp      sssssssssss    "
    print "\t                                p:::::p                             "
    print "\t                                p:::::p                             "
    print "\t                               p:::::::p                            "
    print "\t                               p:::::::p                            "
    print "\t                               p:::::::p                            "
    print "\t                               ppppppppp                            "
    print "\n\n\n\n"
    return

ascipres()

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
programinfo = "Nips v1.0 - Portsweep by Fabrimat"

# Console colors
W = '\033[0m'    # (normal)
R = '\033[31m'   # red
G = '\033[32m'   # green
O = '\033[33m'   # orange
B = '\033[34m'   # blue
P = '\033[35m'   # purple
C = '\033[36m'   # cyan
GR = '\033[37m'  # gray
T = '\033[93m'   # tan

#Configuring logging
logger = logging.getLogger('LogScanner')
logging.basicConfig(filename='Nips.log',format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',level=logging.DEBUG)

#Presentation
print R + programinfo + W
print T + "... type enter to continue " + W
raw_input()

cls()

# Start log session in the log file
logging.info('######### NEW LOG SESSION ########')
logging.info('%s',programinfo)

#Ask for inputs
print R + programinfo + W
print T + "Please enter the inputs.\n" + W
iprange=raw_input("Enter the ip range " + GR + "( ex: 192.168.0 )" + W + " - ")
logging.info('IP Range: %s',iprange)
port=input("Enter the port " + GR + "( ex: 80 )" + W + " - ")
logging.info('Port: %s',port)
showerr=raw_input("Print only the active ips? "+ GR + "(y/n)" + W + " - ")
logging.info('Only active ips? %s',showerr)
showhost=raw_input("Show the hostnames? " + GR + "(y/n)" + W + " - ")
logging.info('Hostnames? %s',showhost)
#socketdeftime=input("Enter the timeout " + GR + "( ex: 0.5 )" + W + " - ")

#A little alert
print("")
print 'The outputs will be saved as ' + GR + '"Nips.log"' + W + '.'
time.sleep(0.5)
print ("")

#Checking errors
if iprange == "" or type(port) != int or port == 0 or len(iprange) > 11 or len(iprange) < 5 or iprange.count(".") != 2 or (showerr != "y" and showerr != "n") or(showhost != "y" and showhost != "n"):
    print "-=" * 21
    print R + "Please check your inputs and try again..." + W
    print "-=" * 21
    logging.error('Invalid Inputs: %s - %s - %s - %s - %s',iprange,type(port),port,len(iprange),iprange.count("."))
    sys.exit()

try:
    # Check what time the scan started
    t1 = datetime.now()
    #Start pinging and scanning
    print GR + "Scanning ip range " + C,iprange + ".1 - " + iprange + ".255" + W
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
                    if result == 0:
                        print "\tPort" ,port, ":" + G + " Open" + W
                        logging.info('Port %s: Open',port)
                        opn = opn + 1
                    else:
                        print "\tPort" ,port, ":" + R + " Closed" + W
                        logging.info('Port %s: Closed',port)
                        clsd = clsd + 1
                    if showhost == "y":
                        try:
                            host = socket.gethostbyaddr(ip)
                            print "\tHostname:",host[0]
                            logging.info("Hostname: %s",host[0])
                            logging.info("Alias list: %s",host[1])
                            logging.info("Ip Addresses List: %s",host[2])
                            host = None, None, None
                        except socket.error:
                            logging.info("Hostname: Empty.")
                    sock.close()

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
print "Active ips \t[ " + C,act, W + " ]"
print "Error ips \t[ " + C,err, W + " ]"
print "No response ips [ " + C,nrp, W + " ]"
print "Open ports   \t[ " + C,opn, W + " ]"
print "Closed ports \t[ " + C,clsd, W + " ]"
print ""
print "Good bye!"
