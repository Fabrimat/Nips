#!/usr/bin/env python2
'''
    Nips v1.1 - Portsweep
    Author: Fabrimat
    Repository: https://github.com/Fabrimat/Nips
'''
import os
import time
from subprocess import Popen
import socket
import subprocess
import sys
from datetime import datetime
import logging

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

#Define global variables
programinfo = "Nips v1.1 - Portsweep by Fabrimat"

# Clear the screen
def cls():
    if os.name == "posix":
        os.system('clear')
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
    print "\t                               ppppppppp                        v1.1"
    print "\n\n\n\n"

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
error = 0
showerr = "y"
showhost = "n"

#Configuring logging
logger = logging.getLogger('LogScanner')
logging.basicConfig(filename='nips.log',format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',level=logging.DEBUG)

#Presentation
print R + programinfo + W
print T + "... type enter to continue " + W
raw_input()

cls()

# Start log session in the log file
logging.info('######### NEW LOG SESSION ########')
logging.info('%s',programinfo)

#Ask for inputs
try:
    print R + programinfo + W
    print T + "Please enter the inputs.\n" + W
    iprange=raw_input( G + "Enter the ip range " + GR + "( ex: 192.168.0 )" + W + " - ")
    logging.info('IP Range: %s',iprange)
    port=input( G + "Enter the port " + GR + "( ex: 80 )" + W + " - ")
    logging.info('Port: %s',port)
    showerr=raw_input( G + "Print only the active ips? "+ GR + "(y/n)" + W + " - ")
    logging.info('Only active ips? %s',showerr)
    showhost=raw_input( G + "Show the hostnames? " + GR + "(y/n)" + W + " - ")
    logging.info('Hostnames? %s',showhost)
    #socketdeftime=input("Enter the timeout " + GR + "( ex: 0.5 )" + W + " - ")
except NameError:
    error = 1


#A little alert
print("")
print  G + 'The outputs will be saved as ' + GR + '"nips.log"' + G + '.' + W
time.sleep(0.5)
print ("")

#Checking errors
if iprange == "" or len(iprange) > 11 or len(iprange) < 5 or iprange.count(".") != 2:
    print G + "-=" * 29
    print R + "Invalid Ip, please check your inputs and try again..." + W
    print G + "-=" * 29
    logging.error('Invalid Ip: %s. Please use the following template: 192.168.0',iprange)
    error = 1
if type(port) != int or port < 1 or port > 65535:
    print G + "-=" * 29
    print R + "Invalid Port, please check your inputs and try again..." + W
    print G + "-=" * 29
    logging.error('Invalid Port: %s. Enter a valid value (1 - 65535)',port)
    error = 1
if (showerr != "y" and showerr != "n" and showerr != "yes" and showerr != "no") or(showhost != "y" and showhost != "n" and showhost != "yes" and showhost != "no"):
    print G + "-=" * 29
    print R + "Invalid Inputs, please check your inputs and try again..." + W
    print G + "-=" * 29
    logging.error('Invalid Inputs: %s - %s. Enter a valid integer value (y/n)',showerr,showhost)
    error = 1
if error == 1:
    print ""
    sys.exit('Check nips.log for details.\n')

try:
    # Check what time the scan started
    t1 = datetime.now()
    #Start pinging and scanning
    print GR + "Scanning ip range " + C,iprange + ".0 - " + iprange + ".255" + R
    logging.info('Scanning ip range')
    print ("")
    for n in range(0,255): # start ping processes
        ip = iprange+".%d" % n
        p.append((ip, Popen(['ping', '-c', '3', ip], stdout=devnull)))

    print GR + "Starting port scan. This can be take a while." + R
    logging.info('Starting port scan.')
    print ("")

    while p:
        for i, (ip, proc) in enumerate(p[:]):
            if proc.poll() is not None: # ping finished
                p.remove((ip, proc)) # this makes it O(n**2)
                if proc.returncode == 0:
                    print T + ip + GR + ':' + G + ' active' + W
                    logging.info('%s active',ip)
                    act = act + 1
                    socket.setdefaulttimeout(0.5)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        print GR + "\tPort" + T ,port, GR + ":" + G + " Open" + W
                        logging.info('Port %s: Open',port)
                        opn = opn + 1
                    else:
                        print GR + "\tPort" + T ,port, GR + ":" + R + " Closed" + W
                        logging.info('Port %s: Closed',port)
                        clsd = clsd + 1
                    if showhost == "y" or showhost == "yes":
                        try:
                            host = socket.gethostbyaddr(ip)
                            print GR + "\tHostname:"+ G,host[0], W
                            logging.info("Hostname: %s",host[0])
                            logging.info("Alias list: %s",host[1])
                            logging.info("Ip Addresses List: %s",host[2])
                            host = None, None, None
                        except socket.error:
                            logging.info("Hostname: Empty.")
                    sock.close()

                elif proc.returncode == 2:
                    if showerr == "n" or showerr == "no":
                        print T + ip + GR + ':' + R + ' no response' + W
                        logging.info('%s no response',ip)
                    nrp=nrp+1
                else:
                    if showerr == "n" or showerr == "no":
                        print T + ip + GR + ':' + R + ' error' + W
                        logging.info('%s error',ip)
                    err=err+1
        time.sleep(.04)
    devnull.close()
    #Stop pinging and scanning

#Errors outputs
except KeyboardInterrupt:
    sys.exit(R + "\n You pressed Ctrl+C" + W)
    logging.info('You pressed Ctrl+C')

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
print ""
print GR + 'Scanning Completed in: '+ C, total, W
print ""
print GR + "-=" * 15 + W
print R + "\tNetwork status" + W
print GR + "-=" * 15 + W
print G + "Active ips \t" + GR + "[ " + C,act, GR + " ]" + W
print R + "Error ips \t" + GR + "[ " + C,err, GR + " ]" + W
print R + "No response ips " + GR + "[ " + C,nrp, GR + " ]" + W
print G + "Open ports   \t" + GR + "[ " + C,opn, GR + " ]" + W
print R + "Closed ports \t" + GR + "[ " + C,clsd, GR + " ]" + W
print ""
print P + "Good bye!" + W
