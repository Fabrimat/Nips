#!/usr/bin/env python2
'''
    Nips v2.0 - Portsweep
    Author: Fabrimat
    Repository: https://github.com/Fabrimat/Nips
'''
import os
import sys
if os.name != "posix":
    sys.exit("\nOS not supported.\n")
import time
from subprocess import Popen
import socket
import subprocess
from datetime import datetime
import logging
import fcntl
import struct

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
programinfo = "Nips v2.0 - Portsweep by Fabrimat"

# Clear the screen
def cls():
    os.system('clear')

def asciipres():
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
    print "\t                               ppppppppp                        v2.0"
    print "\n\n\n\n"

    #Presentation
    print R + programinfo + W
    print T + "... type enter to continue " + W
    raw_input()

    # Start log session in the log file
    logging.info('######### NEW LOG SESSION ########')
    logging.info('%s',programinfo)

if os.name != "nt":
    import fcntl
    import struct

def get_interface_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
                            ifname[:15]))[20:24])

def get_lan_ip():
    iplan = socket.gethostbyname(socket.gethostname())
    if iplan.startswith("127.") and os.name != "nt":
        interfaces = [
            "eth0",
            "eth1",
            "eth2",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
            ]
        for ifname in interfaces:
            try:
                iplan = get_interface_ip(ifname)
                break
            except IOError:
                pass
    return iplan

#Define variables
p = [] # ip -> process
devnull = open(os.devnull, 'wb')
error = 0
showerr = "y"
showhost = "n"

#Configuring logging
logger = logging.getLogger('LogScanner')
logging.basicConfig(filename='nips.log',format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',level=logging.DEBUG)

def inputs():
    error = 0
    #Ask for inputs
    try:
        print R + programinfo + W
        print T + "Please enter the inputs or leave empty to use default values.\n" + W
        iprangefrom=raw_input( G + "Enter the initial ip " + GR + "( ex: 192.168.0.1 )" + W + " - ")
        logging.info('Initial ip: %s',iprangefrom)
        iprangeto=raw_input( G + "Enter the final ip " + GR + "( ex: 192.168.0.254 )" + W + " - ")
        logging.info('Final ip: %s',iprangeto)
        portrangefrom=raw_input( G + "Enter the initial port " + GR + "( ex: 80 )" + W + " - ")
        logging.info('Initial port: %s',portrangefrom)
        portrangeto=raw_input( G + "Enter the final port " + GR + "( ex: 80 )" + W + " - ")
        logging.info('Final port: %s',portrangeto)
        showerr=raw_input( G + "Print only the active ips? "+ GR + "(y/n)" + W + " - ")
        logging.info('Only active ips? %s',showerr)
        showhost=raw_input( G + "Show the hostnames? " + GR + "(y/n)" + W + " - ")
        logging.info('Hostnames? %s',showhost)
        #socketdeftime=input("Enter the timeout " + GR + "( ex: 0.5 )" + W + " - ")
    except NameError:
        error = 1

    #Defalut values
    if iprangefrom == "":
        lan_ip = get_lan_ip()
        lan_ip_split = lan_ip.split('.')
        lan_ip_split[3] = "1"
        iprangefrom = lan_ip_split[0] + '.' + lan_ip_split[1] + '.' + lan_ip_split[2] + '.' + lan_ip_split[3]
    if iprangeto == "":
        lan_ip = get_lan_ip()
        lan_ip_split = lan_ip.split('.')
        lan_ip_split[3] = "254"
        iprangeto = lan_ip_split[0] + '.' + lan_ip_split[1] + '.' + lan_ip_split[2] + '.' + lan_ip_split[3]
    if portrangefrom == "":
        portfrom = 80
    else:
        portfrom = int(portrangefrom)
    if portrangeto == "":
        portto = 80
    else:
        portto = int(portrangeto) + 1
    if portfrom == portto:
        portto = portto + 1
    if portfrom > portto:
        portto = portfrom + 1
    if showerr == "":
        showerr = "y"
    if showhost == "":
        showhost = "y"

    #Logging effective inputs
    logging.info('Initial ip: %s',iprangefrom)

    #A little alert
    print("")
    print  G + 'The outputs will be saved as ' + GR + '"nips.log"' + G + '.' + W
    time.sleep(1)
    print ("")

    #Checking errors
    ipfromcheck = iprangefrom.split('.')
    iptocheck = iprangeto.split('.')
    ipfromcheck0 = int(ipfromcheck[0])
    ipfromcheck1 = int(ipfromcheck[1])
    ipfromcheck2 = int(ipfromcheck[2])
    ipfromcheck3 = int(ipfromcheck[3])
    iptocheck0 = int(iptocheck[0])
    iptocheck1 = int(iptocheck[1])
    iptocheck2 = int(iptocheck[2])
    iptocheck3 = int(iptocheck[3])

    if ipfromcheck0 < 1 or ipfromcheck0 > 254 or ipfromcheck1 < 0 or ipfromcheck1 > 254 or ipfromcheck2 < 0 or ipfromcheck2 > 254 or ipfromcheck3 < 1 or ipfromcheck3 > 254:
        print G + "-=" * 31
        print R + "Invalid initial ip, please check your inputs and try again..." + W
        print G + "-=" * 31
        logging.error('Invalid initial ip: %s.',ipfromcheck)
        error = 1
    if iptocheck0 < 1 or iptocheck0 > 254 or iptocheck1 < 0 or iptocheck1 > 254 or iptocheck2 < 0 or iptocheck2 > 254 or iptocheck3 < 1 or iptocheck3 > 254:
        print G + "-=" * 31
        print R + "Invalid final ip, please check your inputs and try again..." + W
        print G + "-=" * 31
        logging.error('Invalid final ip: %s.',iptocheck)
        error = 1
    if portfrom < 0 or portfrom > 65536:
        print G + "-=" * 31
        print R + "Invalid initial port, please check your inputs and try again..." + W
        print G + "-=" * 31
        logging.error('Invalid initial port: %s. Enter a valid value (1 - 65535)',port)
        error = 1
    if portto < 0 or portto > 65536:
        print G + "-=" * 31
        print R + "Invalid final port, please check your inputs and try again..." + W
        print G + "-=" * 31
        logging.error('Invalid final port: %s. Enter a valid value (1 - 65535)',port)
        error = 1
    if (showerr != "y" and showerr != "n" and showerr != "yes" and showerr != "no") or(showhost != "y" and showhost != "n" and showhost != "yes" and showhost != "no"):
        print G + "-=" * 31
        print R + "Invalid Inputs, please check your inputs and try again..." + W
        print G + "-=" * 31
        logging.error('Invalid Inputs: %s - %s. Enter a valid integer value (y/n)',showerr,showhost)
        error = 1
    if error == 1:
        print ""
        sys.exit('Check nips.log for details.\n')
    #inputs = (iprangefrom, iprangeto, portfrom, portto, showerr, showhost)
    return iprangefrom, iprangeto, portfrom, portto, showerr, showhost;

def scan_process(inputs):
    iprangefrom = inputs[0]
    iprangeto = inputs[1]
    portfrom = inputs[2]
    portto = inputs[3]
    showerr = inputs[4]
    showhost = inputs[5]
    act=0
    nrp=0
    err=0
    opn=0
    clsd=0
    total=0
    ipfrom = iprangefrom.split('.')
    # Check what time the scan started
    t1 = datetime.now()
    print GR + "Scanning ip range " + C + iprangefrom + GR + " - " + C + iprangeto + GR + "\n This can take a while, please be patient." + R
    logging.info('Scanning ip range')
    print ("")
    while True:
        ipfrom[0] = str(ipfrom[0])
        ipfrom[1] = str(ipfrom[1])
        ipfrom[2] = str(ipfrom[2])
        ipfrom[3] = str(ipfrom[3])
        ipping = ipfrom[0] + '.' + ipfrom[1] + '.' + ipfrom[2] + '.' + ipfrom[3]
        p.append((ipping, Popen(['ping', '-c', '3', ipping], stdout=devnull)))
        if ipping == iprangeto:
            break
        ipfrom[0] = int(ipfrom[0])
        ipfrom[1] = int(ipfrom[1])
        ipfrom[2] = int(ipfrom[2])
        ipfrom[3] = int(ipfrom[3])
        ipfrom[3] = ipfrom[3] + 1
        if ipfrom[3] == 255:
            ipfrom[3] = 0
            ipfrom[2] = ipfrom[2] + 1
        if ipfrom[2] == 255:
            ipfrom[2] = 0
            ipfrom[1] = ipfrom[1] + 1
        if ipfrom[1] == 255:
            ipfrom[1] = 0
            ipfrom[0] = ipfrom[0] + 1
    print GR + "Starting port scan." + R
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
                    for port in range(portfrom, portto):
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
    # Checking the time again
    t2 = datetime.now()

    # Calculates the difference of time, to see how long it took to run the script
    total =  t2 - t1
    return total, act, err, nrp, opn, clsd

def results(scan_process):
    total = scan_process[0]
    act = scan_process[1]
    err = scan_process[2]
    nrp = scan_process[3]
    opn = scan_process[4]
    clsd = scan_process[5]
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

try:
    cls()
    asciipres()
    cls()
    inputs = inputs()
    scan_process = scan_process(inputs)
    results(scan_process)
except KeyboardInterrupt:
    sys.exit("\n You pressed Ctrl+C")
