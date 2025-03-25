# my (Max Donaldson's) function
import pox.proto.arp_responder as ARPResponder
from pox.core import core
import pox
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST

def launch (**kw):
    print("this is a test, if this prints out; then it works!")
    newObby = ICantThinkOfAGoodName()
    core.registerNew(ARPResponder)

class ICantThinkOfAGoodName ():
    def __init__ (self):
        print("test")
        core.addListeners(self)

    def _handle_PacketIn (self, event):
        print("packet!")

    def _handle_GoingUpEvent (self, event):
        core.openflow.addListeners(self)
        print("another test, pray to lordy it works")

    def _handle_ConnectionUp (self, event):
      fm = of.ofp_flow_mod()
      fm.priority -= 0x1000 # lower than the default
      fm.match.dl_type = ethernet.ARP_TYPE
      fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
      event.connection.send(fm)
