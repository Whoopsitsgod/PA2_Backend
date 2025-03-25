# my (Max Donaldson's) function
from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.packet.vlan import vlan
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str, str_to_bool
from pox.lib.recoco import Timer
from pox.lib.revent import EventHalt

import pox.openflow.libopenflow_01 as of

import time

def launch (**kw):
    print("this is a test, if this prints out; then it works!")
    newObby = ICantThinkOfAGoodName()

class ICantThinkOfAGoodName ():
    def __init__ (self):
        core.addListeners(self)

    def _handle_PacketIn (self, event):
        print("packet!")
        print("packet parsed " + event.parsed)
        print("port: " + event.port)
