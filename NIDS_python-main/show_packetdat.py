import eel
import sys
import json
import pprint

eel.init("nidsshowpacket")

def is_port_in_use(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

portdefined = int(sys.argv[1])  # --> argv 1 is port number
# portfree = is_port_in_use(portdefined)
# while not portfree:
#     portdefined += 1
#     portfree = is_port_in_use(portdefined)

@eel.expose

def ret_pktsummaryname():
    return sys.argv[3]

@eel.expose

def get_packetdat():
    pktfile = "temp/showpackettemp/" + sys.argv[2]   # --> argv 2 is pktfile addr
    with open(pktfile, "r") as pfile:
        try:
            # pktdat = pfile.read()
            pktdat = json.load(pfile)
        except:
            pktdat = {"No Data":"No Data"}
    # if pktdat.strip() == "":
    #     pktdat = {"No Data":"No Data"}
    # print("1")
    pprint.pprint(pktdat)
    return pktdat

eel.start("index.html", port=portdefined, size=(900, 500))