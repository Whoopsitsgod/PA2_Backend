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
import pox.lib.packet as pkt
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
    #initialize hardcode table
    self.hardcodeDictionary = {}
    self.connectionTable = {}
    #initialize 
 
  def _handle_ConnectionUp (self, event):
    print(f"Switch %s has come up.", dpid_to_str(event.dpid))
    fm = of.ofp_flow_mod()
    fm.priority -= 0x1000 # lower than the default
    fm.match.dl_type = ethernet.ARP_TYPE
    fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    event.connection.send(fm)

  def _handle_PacketIn (self, event):
    log.debug("packet recieved!")
    #packet handled!
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    # check if packet parsed correctly
    if not packet.parsed:
      log.warning("%s: ignoring unparsed packet", dpid_to_str(dpid))
      return
    
    # TODO: check if this is an alright way of doing things, can I put methods that relate to ICMP packets here?
    a = packet.find('arp')
    # if packet didn't contain an ARP request
    if packet.type == pkt.ethernet.ARP_TYPE:

      #DICTIONARY
      # DPID = source MAC address
      # mac = also source MAC address
      # protosrc = source IP address
      # protodest = desired IP address
      mac = event.connection.eth_addr
      log.debug("this is the source MAC address " + dpid_to_str(dpid))
      log.debug("this is the protosrc (?) " + str(a.protosrc))
      log.debug("this is the mac address (?) " + str(mac))
      log.debug("this is the protodest (?) " + str(a.protodst))
      
      macToSend = None
      # TODO: ask if this is a reasonable way of doing things!
      # this handles figuring out where the MAC address to send to is
      if str(mac) == "00:00:00:00:00:05" or str(mac) == "00:00:00:00:00:06":
        # if the message came from h5 or h6, then use the hardcoded table to find where the 
        macToSend = self.hardcodeDictionary[str(a.protodst)]
      else:
        # TODO: Add a method that prevents if the arp is sent quickly before it can respond. It can sometimes be assigned to *BOTH* h5 and h6
        # now do round robin!
        if str(a.protosrc) in self.connectionTable:
          macToSend = self.connectionTable[str(a.protosrc)]
        else:
          if self.roundRobinSendToH5:
            macToSend = EthAddr("00:00:00:00:00:05")
            self.connectionTable[str(a.protosrc)] = macToSend
            self.roundRobinSendToH5 = False
          else:
            macToSend = EthAddr("00:00:00:00:00:06")
            self.connectionTable[str(a.protosrc)] = macToSend
            self.roundRobinSendToH5 = True
          # add the source's IP address to the table to it's related MAC address
          self.hardcodeDictionary[str(a.protosrc)] = mac

      #send the arp_response
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
      r.hwsrc = macToSend
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


      # this is the client-side flow rules
      flowRules = of.ofp_flow_mod()
      flowRules.match.inport = inport
      flowRules.match.dl_type = pkt.ethernet.IP_TYPE
      flowRules.match.nw_dst = IPAddr("10.0.0.10")

      flowRules.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr("10.0.0.10")))
      flowRules.actions.append(of.ofp_action_dl_addr.set_dst(macToSend))
      # TODO: CHANGE! THIS IS STATIC!
      flowRules.actions.append(of.ofp_action_output(port=5))

    #this is the race condition prevention 
    elif packet.type == pkt.ethernet.IP_TYPE:
      print("placeholder")
      packetMsg = of.ofp_packet_out()
      packetMsg = of.ofp_packet_out(port = of.OFPP_TABLE)
      packetMsg.data = event.ofp
      event.connection.send(msg)

  # tcpdump -n -i h1-eth0
