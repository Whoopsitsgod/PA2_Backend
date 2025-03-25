# my (Max Donaldson's) function
import pox.proto.arp_responder as ARPResponder
from pox.core import core
import pox
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST

def launch (**kw):
    print("this is a test, if this prints out; then it works!")
    newObby = ICantThinkOfAGoodName()

class ICantThinkOfAGoodName ():
    def __init__ (self):
        print("test")
        core.openflow.addListeners(self)

    def _handle_PacketIn (self, event):
        print("packet!")

    def _handle_GoingUpEvent (self, event):
        print("another test, pray to lordy it works")
