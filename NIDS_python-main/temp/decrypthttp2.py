import pyshark

key_path = "C:\\Users\\sengu\\ssl1.log"
pcap_file = 'tcpstreamread.pcap'


cap = pyshark.FileCapture(pcap_file,
                          display_filter="http2.streamid eq 5",
                          override_prefs={'ssl.keylog_file': key_path})

dat = ''
rawvallengthpassed = False
for field, val in cap[0].http2._all_fields.items():
    # if rawvallengthpassed == False:
    #     if field == 'http2.header.name.length':
    #         rawvallengthpassed = True
    # else:
    dat += str(field.split(".")[-1]) + " : " + str(val) + " \n\n"

print(dat)

