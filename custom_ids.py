import scapy.all as scp
import codecs
import PySimpleGUI as sg
import os
import threading
import sys
import pyshark
import socket
import scapy.arch.windows as scpwinarch
import json

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


sg.theme('BluePurple')

pktsummarylist = []
suspiciouspackets = []
suspacketactual = []
lastpacket = ""
sus_readablepayloads = []
all_readablepayloads = []
tcpstreams = []
SSLLOGFILEPATH = "C:\\Users\\sengu\\ssl1.log"
http2streams=[]
logdecodedtls = True

layout = [[sg.Button('STARTCAP', key="-startcap-"),
		sg.Button('STOPCAP', key='-stopcap-'), sg.Button('SAVE ALERT', key='-savepcap-'),
        sg.Button('REFRESH RULES', key='-refreshrules-'),
        sg.Button('SHOW TCP STREAMS', key='-showtcpstreamsbtn-')],
        [sg.Text("ALERT PACKETS", font=('Arial Bold', 14), justification="center")],
		[sg.Listbox(key='-pkts-', size=(100,20), values=suspiciouspackets, enable_events=True), 
        sg.Multiline(size=(60,20), key='-payloaddecoded-'),
        sg.Listbox(key='-http2streams-', size=(60, 20), values=http2streams, enable_events=True)],
        [sg.Text("ALL PACKETS", font=('Arial Bold', 14), justification="center")],
        [sg.Listbox(key='-pktsall-', size=(100,20), values=pktsummarylist, enable_events=True),
        #sg.Multiline(size=(50,20), key='-payloaddecodedall-')
        sg.Listbox(key='-tcpstreams-', size=(60,20), values=tcpstreams, enable_events=True)
        ],
		[sg.Button('EXIT')]]

window = sg.Window('Introduction', layout, size=(1600,800), resizable=True)

updatepktlist = False
pkt_list = []


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
                
                if (str(src).strip() == str(chksrcip).strip() and 
                str(dest).strip() == str(chkdestip).strip() and 
                str(proto).strip() == str(chkproto).strip() and 
                str(dport).strip() == str(chkdestport).strip() and 
                str(sport).strip() == str(chksrcport).strip()):
                
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
                    if updatepktlist:
                        window['-payloaddecoded-'].update(value=sus_readablepayloads[len(suspiciouspackets)])
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
    pktsummarylist.append(f"{len(pktsummarylist)} " + pkt_summary)
    pkt_list.append(pkt)
    sus_pkt, sus_msg = check_rules_warning(pkt)
    if sus_pkt == True:
        suspiciouspackets.append(f"{len(suspiciouspackets)} {len(pktsummarylist) - 1}" + pkt_summary + f" MSG: {sus_msg}")
        suspacketactual.append(pkt)
    
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
sniffthread = threading.Thread(target=scp.sniff, kwargs={"prn":pkt_process, "filter": "", "iface":ifaces[0:7]}, daemon=True)
sniffthread.start()

def show_tcp_stream_openwin(tcpstreamtext):
    layout = [[sg.Multiline(tcpstreamtext, size=(100,50), key="tcpnewwintext")]]
    window = sg.Window("TCPSTREAM", layout, modal=True, size=(1200, 600), resizable=True)
    choice = None
    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
            break
    window.close()

def show_http2_stream_openwin(tcpstreamtext):
    layout = [[sg.Multiline(tcpstreamtext, size=(100,50), key="tcpnewwintext")]]
    window = sg.Window("HTTP2 STREAM", layout, modal=True, size=(1200, 600), resizable=True)
    choice = None
    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
            break
    window.close()

def load_tcp_streams(window):
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
    window["-tcpstreams-"].update(values=[])
    window["-tcpstreams-"].update(values=tcpstreams)

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
        window['-http2streams-'].update(values=http2streams)
        pass


def show_http2_stream(window, streamno):
    
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"
    cap3 = pyshark.FileCapture(
            tcpstreamfilename,
            display_filter = f'http2.streamid eq {str(http2streamindex)}',
            override_prefs={'ssl.keylog_file': SSLLOGFILEPATH}
        )
    #print(cap3[0].http2.stream)
    dat = ""
    decode_hex = codecs.getdecoder("hex_codec")
    for pkt in cap3:
        # for x in pkt[pkt.highest_layer]._get_all_field_lines():
        #     print(x)
        #try:
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

    print(dat)
    formatteddat = dat
    # formatteddat = str(dat, "ascii", "replace")
    #show_tcp_stream_openwin(formatteddat)
    print(formatteddat)

    show_http2_stream_openwin(formatteddat)
    # os.remove(tcpstreamfilename)
    #print(formatteddat)
    pass

def show_tcpstream(window, streamno):
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
    if formatteddat.strip() == "" or len(str(formatteddat.strip)) < 1:
        sg.PopupAutoClose("No data")
    else:
        show_tcp_stream_openwin(formatteddat)
    # os.remove(tcpstreamfilename)
    #print(formatteddat)

while True:

    print(suspiciouspackets)

    event, values = window.read()
    if event == '-refreshrules-':
        process_rules(readrules())
    if event == "-startcap-":
        updatepktlist = True
        incomingpacketlist = []
        inc_pkt_list = []
        suspiciouspackets = []
        suspacketactual = []
        pktsummarylist = []
        sus_readablepayloads = []
        while True:
            event, values = window.read(timeout=10)
            if event == "-stopcap-":
                updatepktlist = False
                break
            if event == '-refreshrules-':
                process_rules(readrules())
            if event == sg.TIMEOUT_EVENT:
                #window['-pkts-'].update(pktsummarylist, scroll_to_index=len(pktsummarylist))
                window['-pkts-'].update(suspiciouspackets, scroll_to_index=len(suspiciouspackets))
                window['-pktsall-'].update(pktsummarylist, scroll_to_index=len(pktsummarylist))
                #window['-payloaddecoded-'].update(value=sus_readablepayloads[len(suspiciouspackets)])
            if event in (None, 'Exit'):
                sys.exit()
                break
            if event == '-pkts-' and len(values['-pkts-']):     # if a list item is chosen
                sus_selected = values['-pkts-']
                #sus_selected_index = int(sus_selected.split()[0][0:2])
                sus_selected_index = window['-pkts-'].get_indexes()[0]
                try:
                    window["-tcpstreams-"].update(scroll_to_index=int(suspacketactual[sus_selected_index].tcp.stream))
                except:
                    pass
                window['-payloaddecoded-'].update(value=sus_readablepayloads[sus_selected_index ])
            if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
                #pktselected = values['-pktsall-']
                pkt_selected_index = window["-pktsall-"].get_indexes()
                try:
                    window["-tcpstreams-"].update(scroll_to_index=int(pkt_list[pkt_selected_index].tcp.stream))
                except:
                    pass
            #     #sus_selected_index = int(sus_selected.split()[0][0:2])
            #     pktselectedindex = window['-pktsall-'].get_indexes()[0]
            #     window['-payloaddecodedall-'].update(value=all_readablepayloads[pktselectedindex])
            if event == "-showtcpstreamsbtn-":
                load_tcp_streams(window)
            if event == "-tcpstreams-":
                streamindex = window["-tcpstreams-"].get_indexes()
                show_tcpstream(window, streamindex)
            if event == "-http2streams-":
                http2streamindex = values[event][0]
                show_http2_stream(window, int(http2streamindex))

    if event == "-http2streams-":
        http2streamindex = values[event][0]
        print(http2streamindex)
        show_http2_stream(window, str(int(http2streamindex)))
    if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
        #pktselected = values['-pktsall-']
        pkt_selected_index = window["-pktsall-"].get_indexes()[0]
        try:
            window["-tcpstreams-"].update(scroll_to_index=int(pkt_list[pkt_selected_index].tcp.stream))
        except:
            pass
    if event == '-savepcap-':
        pcapname = "nettrafic"
        scp.wrpcap(f'.\\savedpcap\\{pcapname}.pcap', inc_pkt_list)
    if event == '-pkts-' and len(values['-pkts-']):     # if a list item is chosen
        sus_selected = values['-pkts-']
        #sus_selected_index = int(sus_selected.split()[0][0:2])
        sus_selected_index = window['-pkts-'].get_indexes()[0]
        try:
            window["-tcpstreams-"].update(scroll_to_index=int(suspacketactual[sus_selected_index].tcp.stream))
        except:
            pass
        window['-payloaddecoded-'].update(value=sus_readablepayloads[sus_selected_index])
    if event == "-showtcpstreamsbtn-":
        load_tcp_streams(window)    
    if event == "-tcpstreams-":
        streamindex = window["-tcpstreams-"].get_indexes()
        show_tcpstream(window, streamindex)            
    # if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
    #             pktselected = values['-pktsall-']
    #             #sus_selected_index = int(sus_selected.split()[0][0:2])
    #             pktselectedindex = window['-pktsall-'].get_indexes()[0]
    #             window['-payloaddecodedall-'].update(value=all_readablepayloads[pktselectedindex])
    if event in (None, 'Exit'):
        break
    


window.close()

# port lookup for rule writing
# >>> from socket import getservbyname, getservbyport
# >>> getservbyname("ssh")
# 22
# >>> getservbyname("domain", "udp")
# 53
# >>> getservbyname("https", "tcp")
# 443