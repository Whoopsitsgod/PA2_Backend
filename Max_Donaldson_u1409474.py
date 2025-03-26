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
 
def launch ():
  core.registerNew(MyComponent)

class MyComponent (object):
  def __init__ (self):
    core.openflow.addListeners(self)
 
  def _handle_ConnectionUp (self, event):
    print(f"Switch %s has come up.", dpid_to_str(event.dpid))
         
  def _handle_PacketIn (self, event):
    print(f"packet recieved!")
    log.debug(event.port)

    dpid = event.connection.dpid
    packet = event.parsed
    a = packet.find('arp')

    log.debug("%s ARP %s %s => %s", dpid_to_str(dpid),
      {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
      'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))

    log.debug("MAC address: " + event.connection.eth_addr)
    log.debug("IP destination: " + a.hwsrc)
    
  def _handle_GoingUpEvent (self, event):
    log.debug("Up...")
