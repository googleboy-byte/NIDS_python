import eel
import scapy.all as scp
import codecs
# import PySimpleGUI as sg
import os
import threading
import sys
import pyshark
import socket
import scapy.arch.windows as scpwinarch
import json
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re
import ipaddress
import subprocess
import yara
import pprint
import glob
import time
import json

eel.init("nidsweb")

def readrules():
    rulefile = "rules.txt"
    ruleslist = []
    with open(rulefile, "r") as rf:
        ruleslist = rf.readlines()
    rules_list = []
    for line in ruleslist:
        if line.startswith("alert"):
            rules_list.append(line)
    print(rules_list)
    return rules_list

alertprotocols = []
alertdestips = []
alertsrcips = []
alertsrcports = []
alertdestports = []
alertmsgs = []

# rule format --> "alert [srcip] [srcport] --> [dstip] [dstport] [msg]" [msg] may include spaces and is not within quotes

def process_rules(rulelist):
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsgs
    alertprotocols = []
    alertdestips = []
    alertsrcips = []
    alertsrcports = []
    alertdestports = []
    alertmsgs = []
    for rule in rulelist:
        rulewords = rule.split()
        if rulewords[1] != "any":
            protocol = rulewords[1]
            alertprotocols.append(protocol.lower())
        else:
            alertprotocols.append("any")
        if rulewords[2] != "any":
            srcip = rulewords[2]
            alertsrcips.append(srcip.lower())
        else:
            alertsrcips.append("any")
        if rulewords[3] != "any":
            srcport = int(rulewords[3])
            alertsrcports.append(srcport)
        else:
            alertsrcports.append("any")
        if rulewords[5] != "any":
            destip = rulewords[5]
            alertdestips.append(destip.lower())
        else:
            alertdestips.append("any")
        if rulewords[6] != "any":
            destport = rulewords[6]
            alertdestports.append(destport.lower())
        else:
            alertdestports.append("any")
        try:
            alertmsgs.append(" ".join([rulewords[x] for x in range(7, len(rulewords))]))
        except:
            pass    

    print(alertprotocols)
    print(alertdestips)
    print(alertsrcips)
    print(alertsrcports)
    print(alertdestports)
    print(alertmsgs)

process_rules(readrules())

deviceiplist = []
for route in scp.read_routes():
    if str(route[4]) not in deviceiplist:
        deviceiplist.append(str(route[4]))
        print(str(route[4]))

pktsummarylist = []
suspiciouspackets = []
suspacketactual = []
lastpacket = ""
sus_readablepayloads = []
all_readablepayloads = []
tcpstreams = []
SSLLOGFILEPATH = "C:\\Users\\mainak\\ssl1.log"
http2streams=[]
logdecodedtls = True
httpobjectindexes = []
httpobjectactuals = []
httpobjecttypes = []
yaraflagged_filenames = []
reqfilepathbase = "./temp/tcpflowdump/"
clearinglists = False
yarafiltering_live = False

# updatepktlist = False
updatepktlist = True
pkt_list = []


def get_http_headers(http_payload):
    try:
        headers_raw = http_payload[:http_payload.index(b"\r\n\r\n") + 2]
        headers = dict(re.findall(b"(?P<name>.*?): (?P<value>.*?)\\r\\n", headers_raw))

    except ValueError as err:
        logging.error('Could not find \\r\\n\\r\\n - %s' % err)
        return None
    except Exception as err:
        logging.error('Exception found trying to parse raw headers - %s' % err)
        logging.debug(str(http_payload))
        return None

    if b"Content-Type" not in headers:
        logging.debug('Content Type not present in headers')
        logging.debug(headers.keys())
        return None   
    return headers

def extract_object(headers, http_payload):
    object_extracted = None
    object_type = None

    content_type_filters = [b'application/x-msdownload', b'application/octet-stream']

    try:
        if b'Content-Type' in headers.keys():
            #if headers[b'Content-Type'] in content_type_filters:              
            object_extracted = http_payload[http_payload.index(b"\r\n\r\n") +4:]
            object_type = object_extracted[:2]
            logging.info("Object Type: %s" % object_type)
            # else:
            #     logging.debug('Content Type did not matched with filters - %s' % headers[b'Content-Type'])
            #     if len(http_payload) > 10:
            #         logging.debug('Object first 50 bytes - %s' % str(http_payload[:50]))
        else: 
            logging.info('No Content Type in Package')
            logging.debug(headers.keys())

        if b'Content-Length' in headers.keys():
            logging.info( "%s: %s" % (b'Content-Lenght', headers[b'Content-Length']))
    except Exception as err:
        logging.error('Exception found trying to parse headers - %s' % err)
        return None, None
    return object_extracted, object_type

def read_http():
    objectlist = []
    objectsactual = []
    objectsactualtypes = []
    objectcount = 0
    global pkt_list
    try:
        os.remove(f".\\temp\\httpstreamread.pcap")
    except:
        pass
    httppcapfile = f".\\temp\\httpstreamread.pcap"
    scp.wrpcap(httppcapfile, pkt_list)
    pcap_flow = scp.rdpcap(httppcapfile)
    sessions_all = pcap_flow.sessions()

    for session in sessions_all:
        http_payload = bytes()
        for pkt in sessions_all[session]:
            if pkt.haslayer("TCP"):
                if pkt["TCP"].dport == 80 or pkt["TCP"].sport == 80 or pkt["TCP"].dport == 8080 or pkt["TCP"].sport == 8080:
                    if pkt["TCP"].payload:
                        payload = pkt["TCP"].payload
                        http_payload += scp.raw(payload)
        if len(http_payload):
            http_headers = get_http_headers(http_payload)

            if http_headers is None:
                continue

            object_found, object_type = extract_object(http_headers, http_payload)

            if object_found is not None and object_type is not None:
                objectcount += 1
                objectlist.append(objectcount-1)
                objectsactual.append(object_found)
                objectsactualtypes.append(object_type)
    
    return objectlist, objectsactual, objectsactualtypes


def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"

def check_rules_warning(pkt):
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsgs
    global sus_readablepayloads
    global updatepktlist

    if 'IP' in pkt:
        try:
            src = pkt['IP'].src
            dest = pkt['IP'].dst
            proto = proto_name_by_num(pkt['IP'].proto).lower()
            #print(proto)
            sport = pkt['IP'].sport
            dport = pkt['IP'].dport

            for i in range(len(alertprotocols)):
                flagpacket = False
                if alertprotocols[i] != "any":
                    chkproto = alertprotocols[i]
                else:
                    chkproto = proto
                if alertdestips[i] != "any":
                    chkdestip = alertdestips[i]
                else:
                    chkdestip = dest
                if alertsrcips[i] != "any":
                    chksrcip = alertsrcips[i]
                else:
                    chksrcip = src
                if alertsrcports[i] != "any":
                    chksrcport = alertsrcports[i]
                else:
                    chksrcport = sport
                if alertdestports[i] != "any":
                    chkdestport = alertdestports[i]
                else:
                    chkdestport = dport
                
                # print("chk \n", str(chksrcip) , str(chkdestip) , str(chkproto) , str(chkdestport) , str(chksrcport))
                # print("act \n", str(src) , str(dest) , str(proto) , str(dport) , str(sport))
                
                if "/" not in str(chksrcip).strip() and "/" not in str(chkdestip).strip():
                    if (str(src).strip() == str(chksrcip).strip() and str(dest).strip() == str(chkdestip).strip() and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True
                if "/" in str(chksrcip).strip() and "/" in str(chkdestip).strip():
                    if (ipaddress.IPv4Address(str(src).strip()) in ipaddress.IPv4Network(str(chksrcip).strip()) and ipaddress.IPv4Address(str(dest).strip()) in ipaddress.IPv4Network(str(chkdestip).strip()) and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True
                if "/" in str(chksrcip).strip() and "/" not in str(chkdestip).strip():
                    if (ipaddress.IPv4Address(str(src).strip()) in ipaddress.IPv4Network(str(chksrcip).strip()) and str(dest).strip() == str(chkdestip).strip() and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True
                if "/" not in str(chksrcip).strip() and "/" in str(chkdestip).strip():                        
                    if (str(src).strip() == str(chksrcip).strip() and ipaddress.IPv4Address(str(dest).strip()) in ipaddress.IPv4Network(str(chkdestip).strip()) and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True

                if flagpacket == True:
                        # print("Match")
                    if proto == "tcp":
                        try:
                            readable_payload = bytes(pkt['TCP'].payload).decode('UTF8','replace')
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting tcp payload!!")
                            print(ex)
                            pass
                    elif proto == "udp":
                        try:
                            readable_payload = bytes(pkt['UDP'].payload).decode('UTF8','replace')
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting udp payload!!")
                            print(ex)
                            pass
                    else:
                        sus_readablepayloads.append("NOT TCP PACKET!!")
                    # if updatepktlist:
                    #     window['-payloaddecoded-'].update(value=sus_readablepayloads[len(suspiciouspackets)])
                    return True, str(alertmsgs[i])
        except:
            pkt.show()
        
    # for protocol in alertprotocols:
    #     if protocol.upper() in pkt:
    #         pass
    return False, ""


def pkt_process(pkt):
    global deviceiplist
    global window
    global updatepktlist
    global suspiciouspackets
    global all_readablepayloads

    pkt_summary = pkt.summary()
        #print("\n", src, " : ", dest, "\n")
        # if dest in deviceiplist:
        #     print(f"\n[*] INCOMING PACKET from \n")
        #     if updatepktlist:
                
        #     lastpacket = pkt_summary
        #     return pkt_summary
    # pktsummaryown = ""
    # try:
    #     pktsummaryown = str(pkt["TCP"].time)
    # except:
    #     pass
    pktsummarylist.append(f"{len(pktsummarylist)} " + pkt_summary)
    pkt_list.append(pkt)
    sus_pkt, sus_msg = check_rules_warning(pkt)
    if sus_pkt == True:
        suspiciouspackets.append(f"{len(suspiciouspackets)} {len(pktsummarylist) - 1}" + pkt_summary + f" MSG: {sus_msg}")
        suspacketactual.append(pkt)
        pktsummarylist[-1] = pktsummarylist[-1] + " suspkt_idx: " + str(len(suspiciouspackets) - 1)

    
    # if 'IP' in pkt:
    #     proto = proto_name_by_num(pkt['IP'].proto).lower()
    #     if proto == "tcp":
    #         try:
    #             readable_payload = bytes(pkt['TCP'].payload).decode('UTF8','replace')
    #             all_readablepayloads.append(readable_payload)
    #         except Exception as ex:
    #             all_readablepayloads.append("Error getting tcp payload!!")
    #             print(ex)
    #             pass
    #     elif proto == "udp":
    #         try:
    #             readable_payload = bytes(pkt['UDP'].payload).decode('UTF8','replace')
    #             all_readablepayloads.append(readable_payload)
    #         except Exception as ex:
    #             all_readablepayloads.append("Error getting udp payload!!")
    #             print(ex)
    #             pass
    #     else:
    #         all_readablepayloads.append("NOT TCP PACKET!!")
    #     if updatepktlist:
    #         window['-payloaddecodedall-'].update(value=all_readablepayloads[-1])
        #print(suspiciouspackets)
    #pkt.show()

    return

ifaces = [str(x["name"]) for x in scpwinarch.get_windows_if_list()]
ifaces1 = [ifaces[6]].append(ifaces[0]) #Ether and VMnet8
sniffthread = threading.Thread(target=scp.sniff, kwargs={"prn":pkt_process, "filter": "", "iface":ifaces[0:5]}, daemon=True)
sniffthread.start()

# def show_tcp_stream_openwin(tcpstreamtext):
#     layout = [[sg.Multiline(tcpstreamtext, size=(100,50), key="tcpnewwintext")]]
#     window = sg.Window("TCPSTREAM", layout, modal=True, size=(1200, 600), resizable=True)
#     choice = None
#     while True:
#         event, values = window.read()
#         if event == "Exit" or event == sg.WIN_CLOSED:
#             break
#     window.close()

# def show_http2_stream_openwin(tcpstreamtext):
#     layout = [[sg.Multiline(tcpstreamtext, size=(100,50), key="tcpnewwintext")]]
#     window = sg.Window("HTTP2 STREAM", layout, modal=True, size=(1200, 600), resizable=True)
#     choice = None
#     while True:
#         event, values = window.read()
#         if event == "Exit" or event == sg.WIN_CLOSED:
#             break
#     window.close()

def load_tcp_streams(window=None):
    global http2streams
    global logdecodedtls
    try:
        os.remove(f".\\temp\\tcpstreamread.pcap")
    except:
        pass
    scp.wrpcap(f".\\temp\\tcpstreamread.pcap", pkt_list)
    global tcpstreams
    tcpstreams = []
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"
    cap1 = pyshark.FileCapture(
        tcpstreamfilename,
        display_filter="tcp.seq==1 && tcp.ack==1 && tcp.len==0",
        keep_packets=True)
    number_of_streams = 0
    for pkt in cap1:
        if pkt.highest_layer.lower() == "tcp" or pkt.highest_layer.lower() == "tls":
            print(pkt.tcp.stream)
            if int(pkt.tcp.stream) > number_of_streams:
                number_of_streams = int(pkt.tcp.stream) + 1
    for i in range(0, number_of_streams):
        tcpstreams.append(i)
    # window["-tcpstreams-"].update(values=[])
    # window["-tcpstreams-"].update(values=tcpstreams)

    if logdecodedtls == True:
        http2streams = []
        cap2 = pyshark.FileCapture(
        tcpstreamfilename,
        display_filter="http2.streamid",
        keep_packets=True)
        #numberofhttp2streams = 0
        for pkt in cap2:
            field_names = pkt.http2._all_fields
            for field_name in field_names:
                http2_stream_id = {val for key, val in field_names.items() if key == 'http2.streamid'}
                http2_stream_id = "".join(http2_stream_id)
            #x1 = str(pkt.http2.stream).split(", ")
            #print(x1)
            #streamid = int(x1[1].strip().split(":")[1].strip())
            #print(streamid)
            if http2_stream_id not in http2streams:
                http2streams.append(http2_stream_id)
        # window['-http2streams-'].update(values=http2streams)
        pass


def show_http2_stream(streamno, window=None):
    
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"
    cap3 = pyshark.FileCapture(
            tcpstreamfilename,
            display_filter = f'http2.streamid eq {str(streamno)}',
            override_prefs={'ssl.keylog_file': SSLLOGFILEPATH}
        )
    #print(cap3[0].http2.stream)
    dat = ""
    decode_hex = codecs.getdecoder("hex_codec")
    http_payload = bytes()
    for pkt in cap3:
        # for x in pkt[pkt.highest_layer]._get_all_field_lines():
        #     print(x)
        #try:
        try:
            payload = pkt["TCP"].payload
            http_payload += scp.raw(payload)
            #does literally nothing because we do not know the encoding format of the payload so scp.raw returns type error
        except:
            pass

        print(pkt.http2.stream)
        if ("DATA" not in pkt.http2.stream):
            http2headerdat = ''
            rawvallengthpassed = False
            print(pkt.http2._all_fields.items())
            for field, val in pkt.http2._all_fields.items():
                if rawvallengthpassed == False:
                    if field == 'http2.header.name.length':
                        rawvallengthpassed = True
                else:
                    #if field.split(".")[-1] != "headers":
                    http2headerdat += str(field.split(".")[-1]) + " : " + str(val) + " \n"
                    print(http2headerdat)
            dat += "\n" + http2headerdat
            # httpdat = "".join("".join({val for key,val in pkt.http2._all_fields.items() if key == 'http2.data.data'}).split(":"))
            # httpdatdecoded = decode_hex(httpdat)[0]
            # dat += httpdatdecoded
            # dat = pkt.pretty_print
            # payload = pkt.http2.payload
            # if hasattr(pkt,'http2'):
            #     if hasattr(pkt.http2,'json_object'):
            #         if hasattr(pkt.http2,'body_reassembled_data'):
            #             avp=json.loads(codecs.decode(pkt.http2.body_reassembled_data.raw_value,'hex'))
            # # encryptedapplicationdata_hex = "".join(payload.split(":")[0:len(payload.split(":"))])
            # # encryptedapplicationdata_hex_decoded = decode_hex(encryptedapplicationdata_hex)[0]
            # # dat += encryptedapplicationdata_hex_decoded
            #             dat += avp
            #print(encryptedapplicationdata_hex_decoded)
        # except Exception as ex:
        #     print(ex)
    
    if len(http_payload):
        http_headers = get_http_headers(http_payload)

        if http_headers is not None:
            object_found, object_type = extract_object(http_headers, http_payload)

            dat += object_type + "\n" + object_found + "\n"


    print(dat)
    formatteddat = dat
    # formatteddat = str(dat, "ascii", "replace")
    #show_tcp_stream_openwin(formatteddat)
    print(formatteddat)

    return formatteddat
    # show_http2_stream_openwin(formatteddat)
    
    # os.remove(tcpstreamfilename)
    #print(formatteddat)
    # pass

def show_tcpstream(streamno, window=None):
    global SSLLOGFILEPATH
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"    
    streamnumber = streamno
    cap = pyshark.FileCapture(
        tcpstreamfilename,
        display_filter = 'tcp.stream eq %d' % streamnumber,
        override_prefs={'ssl.keylog_file': SSLLOGFILEPATH}
    )
    dat = b""
    decode_hex = codecs.getdecoder("hex_codec")
    for pkt in cap:
        # for x in pkt[pkt.highest_layer]._get_all_field_lines():
        #     print(x)
        try:
            payload = pkt.tcp.payload
            encryptedapplicationdata_hex = "".join(payload.split(":")[0:len(payload.split(":"))])
            encryptedapplicationdata_hex_decoded = decode_hex(encryptedapplicationdata_hex)[0]
            dat += encryptedapplicationdata_hex_decoded
            #print(encryptedapplicationdata_hex_decoded)
        except Exception as ex:
            print("showtcpstream excp!!!")
            print(ex)

    formatteddat = str(dat, "ascii", "replace")

    # dat1 = ""
    # try:
    #     if pkt.http > 0:
    #         dat1 += "Stream Index :" , str(pkt.tcp.stream) # to print stream index at the start

    #         dat1 += "\nHTTP LAYER :", str(pkt.http).replace('\\n', '').replace('\\r', '')

    # except:
    #     pass
    #show_tcp_stream_openwin(formatteddat)

    # if formatteddat.strip() == "" or len(str(formatteddat.strip)) < 1:
    #     sg.PopupAutoClose("No data")
    # else:
    #     show_tcp_stream_openwin(formatteddat)

    if formatteddat.strip() == "" or len(str(formatteddat.strip)) < 1:
        return "No Data"
    else:
        return formatteddat
    
    # os.remove(tcpstreamfilename)
    #print(formatteddat)

def yarascan(scanfile, rules):
    matches = []
    if os.path.getsize(scanfile) > 0:
        for match in rules.match(scanfile):
            matches.append({"name":match.rule, "meta":match.meta})

    return matches

def yarafilterstreams(window=None):      # window parameter for calling load_tcp_streams if necessary
    
    global yaraflagged_filenames
    global reqfilepathbase

    yaraflagged_filenames = []
    # check if pcap files already exist for captured streams
    # pcap file names are tcpstreamread.pcap and httpstreamread.pcap
    # they are stored in ./temp/

    if not os.path.isfile("./temp/tcpstreamread.pcap"):
        load_tcp_streams(window)
    if not os.path.isfile("./temp/httpstreamread.pcap"):
        read_http()
    
    # tcpflow64 arguments 
    # -a -r <pcapfile> -o <outputdir>
    
    # clear tcpflowdump directory

    dumpfiles = glob.glob(reqfilepathbase + "*")
    for file in dumpfiles:
        os.remove(file)

    # generate files for packet streams using tcpflow
    subprocess.call("tcpflow64.exe -a -r temp/httpstreamread.pcap -o temp/tcpflowdump/", shell=True)
    subprocess.call("tcpflow64.exe -a -r temp/tcpstreamread.pcap -o temp/tcpflowdump/", shell=True)

    yarafile = "./yararules/rules1.yara"
    yararules = yara.compile(yarafile)      # compile yara rules

    
    matchcount = 1
    results = []
    resultstxt = ""
    for req in os.listdir(reqfilepathbase):
        res = yarascan(os.path.join(reqfilepathbase, req), yararules)
        if res:
            for match in res:
                pprint.pprint(match)
                results.append({"ruleMatched":match["name"]})
                resultstxt += str(matchcount) + ". " + str(match["name"]) + "\n"
                matchcount += 1
            if req != "report.xml":
                yaraflagged_filenames.append(str(match["name"]) + ":::" + req)  # ::: serves as separator
    with open("yararesults.txt", "w") as resfile:                       # for filename and yara rule name
        resfile.write(resultstxt)
    for file in yaraflagged_filenames:
        print(file)
        
    # window["-yaraflaggedstreams-"].update(values=yaraflagged_filenames) #update gui with yara flagged stream filenames
    
    return

# def show_yara_flagged(streamdat):
#     layout = [[sg.Multiline(streamdat, size=(100,50), key="yaranewwintext")]]
#     window = sg.Window("HTTP2 STREAM", layout, modal=True, size=(1200, 600), resizable=True)
#     choice = None
#     while True:
#         event, values = window.read()
#         if event == "Exit" or event == sg.WIN_CLOSED:
#             break
#     window.close()

def event_yaraflagged_selected(stream_idx):
    yarafilename = stream_idx.split(":::")[1]
    filepath = os.path.join(reqfilepathbase, yarafilename)
    with open(filepath, "r", errors="ignore") as yaraflaggedfile:
        yaraflagged_filedat = yaraflaggedfile.read()

    # show_yara_flagged(yaraflagged_filedat)
# updatepktlist = True
# incomingpacketlist = []
# inc_pkt_list = []
# suspiciouspackets = []
# suspacketactual = []
# pktsummarylist = []
# sus_readablepayloads = []

@eel.expose

def update_allpackets_gui():
    global clearinglists
    global updatepktlist
    if clearinglists == False and updatepktlist == True:
        global pktsummarylist
        # print(pktsummarylist)
        return pktsummarylist

@eel.expose

def update_allpackets_nidsflagged_gui():
    global clearinglists
    global updatepktlist
    if clearinglists == False and updatepktlist == True:
        global suspiciouspackets
        # print(pktsummarylist)
        return suspiciouspackets

@eel.expose

def refreshrules():
    print("Refreshing rules")
    try:
        process_rules(readrules())
        return
    except:
        print("Failed to refresh rules")
        sys.exit(1)

@eel.expose

def pausecap():
    global updatepktlist
    updatepktlist = False
    return

@eel.expose

def resumecap():
    global updatepktlist
    updatepktlist = True

@eel.expose

def clearall():
    global clearinglists
    clearinglists = True
    global pktsummarylist
    pktsummarylist = []
    global suspiciouspackets
    suspiciouspackets = []
    global suspacketactual
    suspacketactual = []
    global lastpacket
    lastpacket = ""
    global sus_readablepayloads
    sus_readablepayloads = []
    global all_readablepayloads
    all_readablepayloads = []
    global tcpstreams
    tcpstreams = []
    global http2streams
    http2streams=[]
    global logdecodedtls
    logdecodedtls = True
    global httpobjectindexes
    httpobjectindexes = []
    global httpobjectactuals
    httpobjectactuals = []
    global httpobjecttypes
    httpobjecttypes = []
    global yaraflagged_filenames
    yaraflagged_filenames = []
    # updatepktlist = False
    global updatepktlist
    updatepktlist = True
    global pkt_list
    pkt_list = []

    # updatepktlist = True
    global incomingpacketlist
    incomingpacketlist = []
    global inc_pkt_list
    inc_pkt_list = []
    # time.sleep(3)
    clearinglists = False;
    return

def show_nidsflagged_pkt_newwindow(pktstring):
    subprocess.call("python show_packetdat.py 11236 " + pktstring.replace(" ", "").replace(":", "").replace(".", "").replace("/", "").replace(">", "_")+".pkt", shell=True)

@eel.expose

def show_nidsflagged_packet(pktstring):
    global sus_readablepayloads
    suspktindex = int(pktstring.split(" ")[0])
    with open("temp/temppackets/"+pktstring.replace(" ", "").replace(":", "").replace(".", "").replace("/", "").replace(">", "_")+".pkt", "w", errors="ignore") as pktfile:
        print(sus_readablepayloads[suspktindex])
        pktfile.write(sus_readablepayloads[suspktindex])
    # newthread1 = threading.Thread(target=show_nidsflagged_pkt_newwindow, kwargs={"pktstring": pktstring}, daemon=True)
    # newthread1.start()
    if sus_readablepayloads[suspktindex]:
        return sus_readablepayloads[suspktindex]
    return "No Data"

@eel.expose

def show_packet(pktstring):
    global pkt_list
    pktidx = int(pktstring.split(" ")[0])
    packet = pkt_list[pktidx]
    packet_dict = {}
    for line in packet.show2(dump=True).split('\n'):
        if '###' in line:
            layer = line.strip('#[] ')
            packet_dict[layer] = {}
        elif '=' in line:
            key, val = line.split('=', 1)
            packet_dict[layer][key.strip()] = val.strip()
    pktsummary = pktsummarylist[pktidx]
    decd_pload = None
    if "suspkt_idx" in pktsummary:
        suspktindex = int(pktsummary.split(" ")[-1])
        decd_pload = sus_readablepayloads[suspktindex]
        packet_dict["Payload"] = decd_pload
    filename = str(packet.summary()).replace(" ", "").replace(":", "").replace(".", "").replace("/", "").replace(">", "_") + ".json"
    with open("temp/showpackettemp/" + filename, "w", errors="ignore") as pkt_json_file:
        json.dump(packet_dict, pkt_json_file, ensure_ascii=False, indent=4)
    showpkt_newthread = threading.Thread(target=sp_call_showpkt, kwargs={"jsonfilename":filename, "pktsummary":pktsummary}, daemon=True)
    showpkt_newthread.start()
    return

def sp_call_showpkt(jsonfilename, pktsummary):
    subprocess.call("python show_packetdat.py 11236 " + jsonfilename + " \"PACKET: " + pktsummary + "\"", shell=True)


@eel.expose

def show_mainstream_packet(pktstring_mainstream):
    global pkt_list
    pktindex = int(pktstring_mainstream.split(" ")[0])
    pktobject = pkt_list[pktindex]
    pktsummary = pktsummarylist[pktindex]
    suspkt = None
    suspkt_summary = None
    decd_pload = None
    if "suspkt_idx" in pktsummary:
        suspktindex = int(pktsummary.split(" ")[-1])
        suspkt = suspacketactual[suspktindex]
        suspkt_summary = suspiciouspackets[suspktindex]
        decd_pload = sus_readablepayloads[suspktindex]
    pprint.pprint(pktobject)
    try:
        # raw = pktobject["Raw"].load.decode(errors="ignore")
        raw = pktobject["Raw"].load
    except Exception as e:
        raw = "None"
        print(e)
    print("RAW: " + str(raw))

    pktid = pktsummary.replace(":", "").replace(".", "").replace("/", "").replace(">", "_")
    try:
        srcip = pktobject["IP"].src
    except:
        srcip = pktobject[0].src
    try:
        dstip = pktobject["IP"].dst
    except:
        dstip = pktobject[0].dst
    try:
        proto = pktobject["IP"].proto
        proto = proto_name_by_num(proto)
    except:
        proto = pktobject[0].type
    # pprint.pprint(decd_pload)
    ret_array = {
        "pktid" : pktid,
        "srcip" : srcip,
        "destip": dstip,
        "proto" : proto,
        "payload" : "None",
        "raw" : str(raw),
    }
    if suspkt is not None:
        ret_array["payload"] = decd_pload
    # print(ret_array)
    return ret_array

@eel.expose

def load_streams():
    
    # load tcp/http2 streams
    global tcpstreams
    global http2streams

    load_tcp_streams()

    # load http streams (decoded with tls session keys)
    httpobjectindexes, httpobjectactuals, httpobjecttypes = read_http()

    streams_ret_array = ["HTTP STREAM ::: " + str(stream_idx) for stream_idx in httpobjectindexes]
    for tcpstream in tcpstreams:
        streams_ret_array.append("TCP STREAM ::: " + str(tcpstream))
    for http2stream in http2streams:
        streams_ret_array.append("HTTP2 STREAM ::: " + str(http2stream))
    pprint.pprint(streams_ret_array)
    return streams_ret_array

@eel.expose

def show_stream_data(streamid):
    global httpobjectindexes
    global httpobjectactuals
    global httpobjecttypes
    
    stream_idx = int(streamid.split(":::")[-1].strip())
    streamtype = streamid.split(":::")[0].strip().split("STREAM")[0].strip()
    validstreamtypes = ["HTTP", "TCP", "HTTP2"]
    if streamtype in validstreamtypes:
        if streamtype == "TCP":
            streamdat = show_tcpstream(streamno=stream_idx)
            return streamdat
        if streamtype == "HTTP":
            streamdat = httpobjectactuals[stream_idx]
            return streamdat
        if streamtype == "HTTP2":
            streamdat = show_http2_stream(streamno=stream_idx)
            return streamdat
    return "Failed to fetch stream data!!!" # now show this returned data in nidsweb modal element

eel.start("index.html", port=11235)