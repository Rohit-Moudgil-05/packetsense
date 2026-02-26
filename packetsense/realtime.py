from scapy.all import sniff
import threading


def start_sniffer(iface, duration, handler):
    def runner():
        sniff(iface=iface, prn=handler, timeout=duration, store=False)

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    return t
