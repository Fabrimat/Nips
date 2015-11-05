#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
    Nips v2.2 - Portsweep
    Author: Fabrimat
    Repository: https://github.com/Fabrimat/Nips
'''
import os
import sys
if os.name != "posix":
    sys.exit("\nOS not supported.\n")
    logging.error("%s not supported.",os.name)
import time
from subprocess import Popen
import socket
import subprocess
from datetime import datetime
import logging
import fcntl
import struct
import ipaddress
import ifcfg
import re

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
version = "2.2"
programinfo = "Nips v" + version + " - Portsweep by Fabrimat"

# Clear the screen
def cls():
    logging.info('Clearing screen...')
    os.system('clear')

def asciipres():
    logging.info('Printing the presentation')
    print (G + "\n\n\n")
    print ("\tNNNNNNNN        NNNNNNNN  iiii                                      ")
    print ("\tN:::::::N       N::::::N i::::i                                     ")
    print ("\tN::::::::N      N::::::N  iiii                                      ")
    print ("\tN:::::::::N     N::::::N                                            ")
    print ("\tN::::::::::N    N::::::Niiiiiiippppp   ppppppppp       ssssssssss   ")
    print ("\tN:::::::::::N   N::::::Ni:::::ip::::ppp:::::::::p    ss::::::::::s  ")
    print ("\tN:::::::N::::N  N::::::N i::::ip:::::::::::::::::p ss:::::::::::::s ")
    print ("\tN::::::N N::::N N::::::N i::::ipp::::::ppppp::::::ps::::::ssss:::::s")
    print ("\tN::::::N   N:::::::::::N i::::i p:::::p     p:::::p   s::::::sssssss")
    print ("\tN::::::N  N::::N:::::::N i::::i p:::::p     p:::::p s:::::s         ")
    print ("\tN::::::N    N::::::::::N i::::i p:::::p     p:::::p      s::::::s   ")
    print ("\tN::::::N     N:::::::::N i::::i p:::::p    p::::::pssssss   s:::::s ")
    print ("\tN::::::N      N::::::::Ni::::::ip:::::ppppp:::::::ps:::::ssss::::::s")
    print ("\tN::::::N       N:::::::Ni::::::ip::::::::::::::::p s::::::::::::::s ")
    print ("\tN::::::N        N::::::Ni::::::ip::::::::::::::pp   s:::::::::::ss  ")
    print ("\tNNNNNNNN         NNNNNNNiiiiiiiip::::::pppppppp      sssssssssss    ")
    print ("\t                                p:::::p                             ")
    print ("\t                                p:::::p                             ")
    print ("\t                               p:::::::p                            ")
    print ("\t                               p:::::::p                            ")
    print ("\t                               p:::::::p                            ")
    print ("\t                               ppppppppp                        v" + version)
    print ("\n\n\n\n" + W)

    #Presentation
    print (R + programinfo + W)
    print (T + "... type enter to continue " + W)
    input()

    # Start log session in the log file
    logging.info('######### NEW LOG SESSION ########')
    logging.info('%s',programinfo)

def get_interface_ip(interface):
    logging.info('Testing interfaces...')
    devnull = open(os.devnull, 'wb')
    output = subprocess.Popen(['ifconfig', interface], stdout=subprocess.PIPE, stderr=devnull).communicate()[0]
    logging.info('%s',output)
    ip_lan_value = re.findall('192.168.([0-9]*).[0-9]* ', str(output))[0]
    ip_type=0
    if ip_lan_value == -1:
            ip_lan_value = re.findall('10.([0-9]*.[0-9]*).[0-9]* ', str(output))[0]
            ip_type=1
    logging.info('ip_lan_value is %s',ip_lan_value)
    return (ip_lan_value,ip_type)

def get_lan_ip():
    logging.info('Getting lan ip...')
    iplan = socket.gethostbyname(socket.gethostname())
    print (iplan)
    if iplan.startswith("127."):
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
        for interface in interfaces:
            print (interface)
            try:
                iplan = get_interface_ip(interface)
                break
            except IOError:
                pass
            except IndexError:
                pass
    return iplan

#Configuring logging
logger = logging.getLogger('LogScanner')
logging.basicConfig(filename='nips.log',format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',level=logging.DEBUG)

def inputs():
    logging.info('Starting input requests...')
    error = 0
    #Ask for inputs
    try:
        print (R + programinfo + W)
        print (T + "Please enter the inputs or leave empty to use default values.\n" + W)
        iprangefrom=input( G + "Enter the initial ip " + GR + "( ex: 192.168.0.1 )" + W + " - ")
        logging.info('Initial ip: %s',iprangefrom)
        iprangeto=input( G + "Enter the final ip " + GR + "( ex: 192.168.0.254 )" + W + " - ")
        logging.info('Final ip: %s',iprangeto)
        portrangefrom=input( G + "Enter the initial port " + GR + "( ex: 80 )" + W + " - ")
        logging.info('Initial port: %s',portrangefrom)
        portrangeto=input( G + "Enter the final port " + GR + "( ex: 80 )" + W + " - ")
        logging.info('Final port: %s',portrangeto)
        OnActIp=input( G + "Print only the active ips? "+ GR + "(y/n)" + W + " - ")
        logging.info('Only active ips? %s',OnActIp)
        showhost=input( G + "Show the hostnames? " + GR + "(y/n)" + W + " - ")
        logging.info('Hostnames? %s',showhost)
    except NameError:
        error = 1

    #Defalut values
    lan_ip = get_lan_ip()
    if lan_ip[1]==0:
        if iprangefrom == "":
            iprangefrom = "192.168." + lan_ip[0] + ".1"
            logging.info("Assigned initial ip: %s",iprangefrom)
        if iprangeto == "":
            iprangeto = "192.168." + lan_ip[0] + ".254"
            logging.info("Assigned final ip: %s",iprangeto)
    else:
            if iprangefrom == "":
                iprangefrom = "10." + lan_ip[0] + ".1"
                logging.info("Assigned initial ip: %s",iprangefrom)
            if iprangeto == "":
                iprangeto = "10." + lan_ip[0] + ".254"
                logging.info("Assigned final ip: %s",iprangeto)
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
    if OnActIp == "":
        OnActIp = "y"
    if showhost == "":
        showhost = "y"

    #Logging effective inputs
    logging.info('Effective initial ip: %s',iprangefrom)
    logging.info('Effective final ip: %s',iprangeto)


    #A little alert
    print("")
    print  (G + 'The outputs will be saved as ' + GR + '"nips.log"' + G + '.' + W)
    time.sleep(1)
    print ("")

    #Checking errors
    try:
        if ipaddress.ip_address(iprangefrom) > ipaddress.ip_address(iprangeto):
            print (G + "-=" * 31)
            print (R + "Invalid ips, please check your inputs and try again..." + W)
            print (G + "-=" * 31)
            logging.error('Invalid ips: %s - %s.',iprangefrom,iprangeto)
            error = 1
    except ValueError:
        print (G + "-=" * 31)
        print (R + "Invalid ips, please check your inputs and try again..." + W)
        print (G + "-=" * 31)
        logging.error('Invalid ips: %s - %s.',iprangefrom,iprangeto)
        error = 1
    if portfrom < 0 or portfrom > 65536:
        print (G + "-=" * 31)
        print (R + "Invalid initial port, please check your inputs and try again..." + W)
        print (G + "-=" * 31)
        logging.error('Invalid initial port: %s. Enter a valid value (1 - 65535)',port)
        error = 1
    if portto < 0 or portto > 65536:
        print (G + "-=" * 31)
        print (R + "Invalid final port, please check your inputs and try again..." + W)
        print (G + "-=" * 31)
        logging.error('Invalid final port: %s. Enter a valid value (1 - 65535)',port)
        error = 1
    if (OnActIp != "y" and OnActIp != "n" and OnActIp != "yes" and OnActIp != "no") or(showhost != "y" and showhost != "n" and showhost != "yes" and showhost != "no"):
        print (G + "-=" * 31)
        print (R + "Invalid Inputs, please check your inputs and try again..." + W)
        print (G + "-=" * 31)
        logging.error('Invalid Inputs: %s - %s. Enter a valid integer value (y/n)',OnActIp,showhost)
        error = 1
    if error == 1:
        print ("")
        sys.exit('Check nips.log for details.\n')
    return iprangefrom, iprangeto, portfrom, portto, OnActIp, showhost;

def scan_process(inputs):
    logging.info('Starting scan process...')
    #Define variables
    p = [] # ip -> process
    devnull = open(os.devnull, 'wb')

    iprangefrom = inputs[0]
    iprangeto = inputs[1]
    portfrom = inputs[2]
    portto = inputs[3]
    OnActIp = inputs[4]
    showhost = inputs[5]
    act=0
    nrp=0
    err=0
    opn=0
    clsd=0
    total=0
    # Check what time the scan started
    t1 = datetime.now()
    print (GR + "Scanning ip range " + C + iprangefrom + GR + " - " + C + iprangeto + GR + "\n This can take a while, please be patient." + R)
    logging.info('Scanning ip range')
    print ("")
    while True:
        p.append((iprangefrom, Popen(['ping', '-c', '3', iprangefrom], stdout=devnull, stderr=devnull)))
        if iprangefrom == iprangeto:
            break
        ipp = int(ipaddress.ip_address(iprangefrom)) + 1
        iprangefrom = str(ipaddress.ip_address(ipp))
    print (GR + "Starting port scan." + R)
    logging.info('Starting port scan.')
    print ("")
    while p:
        for i, (iprangefrom, proc) in enumerate(p[:]):
            if proc.poll() is not None: # ping finished
                p.remove((iprangefrom, proc)) # this makes it O(n**2)
                if proc.returncode == 0:
                    print (T + iprangefrom + GR + ':' + G + ' active' + W)
                    logging.info('%s active',iprangefrom)
                    act = act + 1
                    for port in range(portfrom, portto):
                        socket.setdefaulttimeout(0.5)
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        result = sock.connect_ex((iprangefrom, port))
                        if result == 0:
                            print (GR + "\tPort" + T ,port, GR + ":" + G + " Open" + W)
                            logging.info('Port %s: Open',port)
                            opn = opn + 1
                        else:
                            print (GR + "\tPort" + T ,port, GR + ":" + R + " Closed" + W)
                            logging.info('Port %s: Closed',port)
                            clsd = clsd + 1
                    if showhost == "y" or showhost == "yes":
                        try:
                            host = socket.gethostbyaddr(iprangefrom)
                            print (GR + "\tHostname:"+ G,host[0], W)
                            logging.info("Hostname: %s",host[0])
                            logging.info("Alias list: %s",host[1])
                            logging.info("Ip Addresses List: %s",host[2])
                            host = None, None, None
                        except socket.error:
                            logging.info("Hostname: None.")
                    sock.close()

                elif proc.returncode == 2:
                    if OnActIp == "n" or OnActIp == "no":
                        print (T + iprangefrom + GR + ':' + R + ' no response' + W)
                        logging.info('%s no response',ip)
                    nrp=nrp+1
                else:
                    if OnActIp == "n" or OnActIp == "no":
                        print (T + iprangefrom + GR + ':' + R + ' error' + W)
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
    logging.info('Printing results...')
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
    print ("")
    print (GR + 'Scanning Completed in: '+ C, total, W)
    print ("")
    print (GR + "-=" * 15 + W)
    print (R + "\tNetwork status" + W)
    print (GR + "-=" * 15 + W)
    print (G + "Active ips \t" + GR + "[ " + C,act, GR + " ]" + W)
    print (R + "Error ips \t" + GR + "[ " + C,err, GR + " ]" + W)
    print (R + "No response ips " + GR + "[ " + C,nrp, GR + " ]" + W)
    print (G + "Open ports   \t" + GR + "[ " + C,opn, GR + " ]" + W)
    print (R + "Closed ports \t" + GR + "[ " + C,clsd, GR + " ]" + W)
    print ("")
    print (P + "Good bye!" + W)

if __name__=='__main__':
    try:
        logging.info('Starting program...')
        cls()
        asciipres()
        logging.info
        cls()
        inputs = inputs()
        scan_process = scan_process(inputs)
        results(scan_process)
    except KeyboardInterrupt:
        sys.exit("\n You pressed Ctrl+C")
        logging.info('Ctrl+C. Exiting...')
