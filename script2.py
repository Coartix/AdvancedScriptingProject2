import sys
import subprocess           #Helps for ICMP scan
import scapy.all as scapy   #Helps for ARP scan
import ipaddress            #Helps identifying true IP address
import errno                #Helps to classify errors for TCP and UDP scan
import math                 #Helps calculate time to wait or numbers of ports to synchronize for scan
import select               #Provides access to the select() and poll() functions
import socket               #Helps for creating TCP and UDP scan
import time                 #Wait before proceeding further into the UDP or TCP scan

################# TCP and UDP section ###################


TCP_ASYNC_LIMIT = 256      # number of tcp ports to scan concurrently
TCP_CONNECT_POLLTIME = 12  # seconds poll waits for async tcp connects

UDP_ASYNC_LIMIT = 256      # max udp ports to scan concurrently
UDP_RETRIES = 8            # default number of udp retransmissions
UDP_WAIT = 1               # default wait seconds before retry + receive
UDP_ICMP_RATE_LIMIT = 1    # wait seconds after inferred icmp unreachable

# The Probe class classify attributes of each ip:port group per scan type
class Probe():
    """
    simple probe state, one per ip:port per scan type
    """
    def __init__(self, ip, port, _type=socket.SOCK_STREAM):
        self.type = _type
        self.ip = ip
        self.port = port
        self.status = None
        self.socket = socket.socket(socket.AF_INET, _type)

    def handle_udp_econnrefused(self):
        # even numbered sends will fail with econnrefused
        # this is used to detect icmp unreachable errors
        self.status = False
        self.socket.close()
        print('udp port {} closed'.format(self.port))

    def handle_udp_receive(self):
        self.status = True
        self.socket.close()
        print('udp port {} open'.format(self.port))
        try:
            print("Service name: %s\n" % socket.getservbyport(self.port, 'udp'))
        except OSError:
            print("Cannot get service name due to OSError.\n")


# UDP scan
def udp_scan(ip, ports, initial_sends=1, retries=UDP_RETRIES, wait=UDP_WAIT,
                icmp_rate_limit=UDP_ICMP_RATE_LIMIT):
    """
    scan for open+filtered udp ports
    returns: open_ports, maybe_open_ports
    """
    print('udp scanning %d ports' % (len(ports)))

    probes = []
    for port in ports:
        probe = Probe(ip, port, socket.SOCK_DGRAM)
        probes.append(probe)
        sock = probe.socket

        sock.setblocking(0)
        sock.connect((probe.ip, probe.port))  # allow icmp unreachable detect

        # initial_sends allows us to implement udp_scan as a simple wrapper
        # at the expense of slightly complicating udp_scan_ex
        # initial_sends = (initial_sends & ~1) + 1  # always odd
        for i in range(initial_sends):
            if probe.status is not None:
                continue
            try:
                sock.send(bytes(0))
            except socket.error as ex:
                if ex.errno == errno.ECONNREFUSED:
                    probe.handle_udp_econnrefused()
                    break
                else:
                    raise

    for i in range(retries+1):

        time.sleep(wait)

        for probe in probes:
            if probe.status is not None:
                continue
            sock = probe.socket
            try:
                sock.send(bytes(1))
            except socket.error as ex:
                # 2nd send icmp trick to detect closed ports
                # print ex, '* 2nd send', errno.errorcode[ex.errno]
                if ex.errno == errno.ECONNREFUSED:
                    probe.handle_udp_econnrefused()
                    # sleep to deal with icmp error rate limiting
                    time.sleep(icmp_rate_limit)
                    continue
                else:
                    raise

            try:
                sock.recvfrom(8192)
                probe.handle_udp_receive()
                continue
            except socket.error as ex:
                if ex.errno == errno.ECONNREFUSED:
                    print('udp recv failed',
                            errno.errorcode[ex.errno], ex, probe.port)
                    continue
                elif ex.errno != errno.EAGAIN:
                    print('udp recv failed',
                            errno.errorcode[ex.errno], ex, probe.port)
                    raise

    open_ports = []
    maybe_open_ports = []
    for probe in probes:
        if probe.status is False:
            continue
        elif probe.status:
            print('udp port {} open'.format(probe.port))
            open_ports.append(probe.port)
        else:
            print('udp port {} maybe open'.format(probe.port))
            maybe_open_ports.append(probe.port)
            probe.socket.close()

    return open_ports, maybe_open_ports


# TCP scan
def tcp_scan(ip, ports):
    print('\ttcp scanning for %d ports' % (len(ports)))

    open_ports = []
    probes = []
    fileno_map = {}  # {fileno:probe}

    poll = select.epoll(len(ports))
    for port in ports:
        probe = Probe(ip, port)
        sock = probe.socket
        fileno_map[sock.fileno()] = probe

        sock.setblocking(0)
        result = sock.connect_ex((probe.ip, probe.port))

        if result == 0:
            print('Port {}:\tOpened\tImmediate connect'.format(port))
            print("Service name: %s\n" % socket.getservbyport(port, 'tcp'))
            open_ports.append(port)
        elif result == errno.EINPROGRESS:
            # print('pending', probe.port, errno.errorcode[result])
            poll.register(probe.socket,select.EPOLLOUT | select.EPOLLERR | select.EPOLLHUP)
            probes.append(probe)
        else:
            print('tcp connect fail for port: {}\n'.format(port), result, errno.errorcode[result])

    if len(probes) > 0:
        time.sleep(1)

        events = poll.poll(TCP_CONNECT_POLLTIME)

        for fd, flag in events:
            probe = fileno_map[fd]
            #print(probe.port, fd, flag)

            error = probe.socket.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
            if error:
                print('tcp connection bad for port: {} error: {}\n'.format(probe.port,error))

            else:
                print("Port {}:\tOpened".format(probe.port))
                try:
                    print("Service name: %s\n" % socket.getservbyport(probe.port, 'tcp'))
                except OSError:
                    print("Cannot get service name due to OSError.\n")
                open_ports.append(probe.port)

    for probe in probes:
        probe.socket.close()

    poll.close()

    return open_ports

# Segment scanning for more efficiency
def segment(fn, ip, ports, async_limit):
    loops = int(math.ceil(len(ports)/async_limit))
    open_ports = []
    for i in range(loops):
        start = i*async_limit
        stop = (i+1)*async_limit
        result = fn(ip, ports[start:stop])
        if type(result) == tuple:
            open_ports.extend(result[0])
            open_ports.extend(result[1])
        else:
            open_ports.extend(result)
    return open_ports


#################### ARP scan and ICMP scan section #################


def arp_scan(target_ip):
    """
    Performs a network scan by sending ARP requests to an IP address or a range of IP addresses.
    Args:
        ip (str): An IP address or IP address range to scan. For example:
                    - 192.168.1.1 to scan a single IP address
                    - 192.168.1.1/24 to scan a range of IP addresses.
    Returns:
        A list of dictionaries mapping IP addresses to MAC addresses. For example:
        [
            {'IP': '192.168.2.1', 'MAC': 'c4:93:d9:8b:3e:5a'}
        ]
    """

    # IP Address for the destination
    # create ARP packet
    arp = scapy.ARP(pdst=target_ip)
    # create the Ether broadcast packet
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack them
    packet = ether / arp

    result = scapy.srp(packet, timeout=1, verbose=0)[0]

    # a list of clients, we will fill this in the upcoming loop
    clients = []

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    # print clients
    return clients



def icmp_scan(address):
    res = subprocess.call(['ping', '-c', '3', address], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if res == 0:
        print("The %s address can be ping." % address)

#################################################################

# Main function taking care of the inputs and the calling of the functions
def main():
    try:
        command = sys.argv[1]
    except:
        print("Command missing.\nThe commands are:\n\t-a, --arp for ARP scan\n\t-i, --icmp for ICMP scan\n\t-t, --tcp for TCP scan\n\t-u, --udp for UDP scan\n\nWith -u or -t command -p command can be used to specify a port.")
        sys.exit(1)

    try:
        IP = sys.argv[2]
    except:
        print("IP missing.")
        sys.exit(1)

    L_IP = []

    #Next lines take into consideration the given range of IP address: IP_address-IP_address
    if "-" in IP:
        try:
            L = IP.split("-")
            if L and L[0].rfind(".") != -1:
                beginning = int(L[0][L[0].rfind(".") + 1:])
                end = int(L[1][L[1].rfind(".") + 1:])
                IP_begin = L[0][:L[0].rfind(".") + 1]
            else:
                raise Exception
            if end < beginning or end > 254 or beginning > 254 or end < 0 or beginning < 0 or L[1][:L[1].rfind(
                    ".") + 1] != IP_begin:
                raise Exception
            else:
                for i in range(beginning, end + 1):
                    L_IP.append(IP_begin + str(i))
        except:
            print('IP is invalid.')
            sys.exit(1)

    # Check IP or subnet
    else:
        try:
            ip = ipaddress.IPv4Address(IP)
        except:
            try:
                ip = ipaddress.IPv4Network(IP)
            except:
                print('IP is invalid. If subnet only X.X.X.0/24 works.')
                sys.exit(1)



    # ARP Scan
    if command == "-a" or command == '--arp':
        print('[*] Start to scan type Ctrl+c if you want to stop the python script [*]')
        print("Available devices:")
        print("IP" + " " * 18 + "MAC")

        if not L_IP:
            clients = arp_scan(IP)
            for client in clients:
                print("{:16}    {}".format(client['ip'], client['mac']))

        else:
            for ip in L_IP:
                clients = arp_scan(ip)
                for client in clients:
                    print("{:16}    {}".format(client['ip'], client['mac']))

    # ICMP Scan
    elif command == '-i' or command == '--icmp':
        print('[*] Start to scan type Ctrl+c if you want to stop the python script [*]')
        if L_IP:
            for ip in L_IP:
                icmp_scan(ip)
        else:
            if IP.endswith("/24"):
                IP = IP[:IP.rfind(".") + 1]
                for ip in range(255):
                    icmp_scan(IP + str(ip))
            elif IP.endswith("/32"):
                IP = IP[:-3]
                icmp_scan(IP)
            else:
                icmp_scan(IP)

    # TCP or UDP scan
    elif ((command == '-t' or command == '--tcp') or (command == '-u' or command == '--udp')):
        # Networks are not arguments for tcp or udp scan
        if not L_IP:
            if len(sys.argv) == 3:
                print("Scanning default ports [1-500]")
                L_ports = [i for i in range(1, 501)]
            elif len(sys.argv) >= 5:
                if sys.argv[3] != '-p':
                    print("Wrong command to enter ports or command -p missing.")
                    sys.exit(1)
                L_ports = []

                try:
                    ports = sys.argv[4]
                    if "-" in ports and "," in ports:
                        L_bis = ports.split(",")
                        for i in range(len(L_bis)):
                            if "-" in L_bis[i]:
                                L_bis2 = [i for i in range(int(L_bis[i].split("-")[0]), int(L_bis[i].split("-")[1]))]
                                for port in L_bis2:
                                    L_ports.append(port)
                            else:
                                L_ports.append(int(L_bis[i]))

                    elif "-" in ports:
                        L_ports = [port for port in range(int(ports.split("-")[0]), int(ports.split("-")[1]))]
                    elif "," in ports:
                        L_ports = [int(port) for port in ports.split(",")]
                    else:
                        L_ports.append(int(ports))
                except Exception as error:
                    print(error)
                    print("You need to put a port or a range of ports.\nExample:\n\tx\n\tx,y,...\n\tx-y\n\tx-y,z")
                    sys.exit(1)
            else:
                print("Missing the port.\nYou need to put a port or a range of ports.\nExample:\n\tx\n\tx,y,...\n\tx-y\n\tx-y,z")
                sys.exit(1)

            # TCP Scan
            if command == '-t' or command == '--tcp':
                try:
                    print('[*] Start to scan type Ctrl+c if you want to stop the python script [*]')
                    tcp_ports = segment(tcp_scan, IP, L_ports, TCP_ASYNC_LIMIT)
                    print("To resume here are the open ports:\n", *sorted(tcp_ports))
                    print("All other ports are closed.")
                except ValueError as error:
                    print(error)
                    sys.exit(1)

            # UDP scan
            elif command == '-u' or command == '--udp':
                try:
                    print('[*] Start to scan type Ctrl+c if you want to stop the python script [*]')
                    estimated = round(len(L_ports) / 60) + 1
                    print('Rough estimated udp completion: %d minutes' % (estimated))
                    udp_ports = segment(udp_scan, IP, L_ports, UDP_ASYNC_LIMIT)
                    print("To resume here are the open ports:\n", *sorted(udp_ports))
                    print("All other ports are closed.")
                except ValueError as error:
                    print(error)
                    sys.exit(1)

        else:
            print("TCP scan do not take network as argument.")
            sys.exit(1)

    else:
        print("%s is a wrong command.\nThe commands are:\n\t-a, --arp for ARP scan\n\t-i, --icmp for ICMP scan\n\t-t, --tcp for TCP scan\n\t-u, --udp for UDP scan\n\nWith -u or -t command -p command can be used to specify a port." % command)


#   Calls at the beginning of the script the function main
if __name__ == '__main__':
    main()
