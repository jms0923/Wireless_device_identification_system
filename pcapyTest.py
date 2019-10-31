import pcapy
import dpkt


def pktHandler(header, payload):

    pkt = dpkt.ieee80211.IEEE80211(payload)
    # print(pkt.__sizeof__())

    print(pkt)


if __name__ == '__main__':
    devList = pcapy.findalldevs()
    # print(devList)
    dev = 'wlan0mon'
    cap = pcapy.open_live(dev, 65536, True, 0)
    readerDev = pcapy.create(dev)

    cap.loop(10000, pktHandler)
    # cap.dispatch(10000, pktHandler)
