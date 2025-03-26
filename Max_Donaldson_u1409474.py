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
    
    if not a: 
      log.debug("Packet did not contain ARP request")
      return

    mac = event.connection.eth_addr
    sourceIp = a.hwsrc

    
    
  def _handle_GoingUpEvent (self, event):
    log.debug("Up...")
