# my (Max Donaldson's) function
# TO ASK TA:
# is the _handle_packet set up correctly?
# - it takes ~5-20 minutes to get packet and the packet it recieves is not an ARP request. Possibly could be from POWDER itself
# 

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
    self.roundRobinSendToH5 = True
 
  def _handle_ConnectionUp (self, event):
    print(f"Switch %s has come up.", dpid_to_str(event.dpid))
    fm = of.ofp_flow_mod()
    fm.priority -= 0x1000 # lower than the default
    fm.match.dl_type = ethernet.ARP_TYPE
    fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    event.connection.send(fm)

  # SHOULD fire when s1 (the controller/switch) recieves a packet, but does not all the time.
  def _handle_PacketIn (self, event):
    print(f"packet recieved!")
    log.debug(event.port)

    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    # check if packet parsed correctly
    if not packet.parsed:
      log.warning("%s: ignoring unparsed packet", dpid_to_str(dpid))
      return
    
    a = packet.find('arp')
    # if packet didn't contain an ARP request
    if not a: 
      log.debug("Packet did not contain ARP request")
      return
    
    mac = event.connection.eth_addr
    sourceIp = a.hwsrc

    #DICTIONARY
    # DPID = source MAC address
    # mac = also source MAC address
    # protosrc = source IP address
    # protodest = desired IP address
    log.debug("this is the source MAC address " + dpid_to_str(dpid))
    log.debug("this is the protosrc (?) " + str(a.protosrc))
    log.debug("this is the mac address (?) " + str(mac))
    log.debug("this is the protodest (?) " + str(a.protodst))
    
    # ask if this is a reasonable way of doing things, if h1 is now always
    # going to
    if self.roundRobinSendToH5:
      r = arp()
      r.hwtype = a.hwtype
      r.prototype = a.prototype
      r.hwlen = a.hwlen
      r.protolen = a.protolen
      r.opcode = arp.REPLY
      r.hwdst = a.hwsrc
      r.protodst = a.protosrc
      r.protosrc = a.protodst
      log.debug("alright, we're getting to the danger zone")
      r.hwsrc = "00:00:00:00:00:05"
      log.debug("past the danger zone!")
      e = ethernet(type=packet.type, src=event.connection.eth_addr,
      dst=a.hwsrc)
      e.payload = r
      if packet.type == ethernet.VLAN_TYPE:
        log.debug("whoopsies, this was needed")
        v_rcv = packet.find('vlan')
        e.payload = vlan(eth_type = e.type,
                                 payload = e.payload,
                                 id = v_rcv.id,
                                 pcp = v_rcv.pcp)
        e.type = ethernet.VLAN_TYPE
      log.debug("%s answering ARP for %s" % (dpid_to_str(dpid),
                str(r.protosrc)))
      msg = of.ofp_packet_out()
      msg.data = e.pack()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
      msg.in_port = inport
      event.connection.send(msg)
    else:
      log.debug("this shouldn't ever fire!")
    
  def _handle_GoingUpEvent (self, event):
    #this doesn't fire, for... some reason.
    log.debug("Up...")

  # NOTES:
  # more arp_responder shows actually what things mean
  # 
  # flows:
  # 
  # tcpdump -n -i h1-eth0
