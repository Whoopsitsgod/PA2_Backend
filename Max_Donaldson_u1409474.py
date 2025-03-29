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
    self.hardcodeDictionary["10.0.0.5"] = EthAddr("00:00:00:00:00:05")
    self.hardcodeDictionary["10.0.0.6"] = EthAddr("00:00:00:00:00:06")
    self.connectionTable = {}
    self.portTable = {}
    self.portTable["10.0.0.5"] = 5
    self.portTable["10.0.0.6"] = 6
    #initialize 
 
  def _handle_ConnectionUp (self, event):
    print(f"Switch %s has come up.", dpid_to_str(event.dpid))
    fm = of.ofp_flow_mod()
    fm.priority -= 0x1000 # lower than the default
    fm.match.dl_type = ethernet.ARP_TYPE
    fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    event.connection.send(fm)

  def _handle_PacketIn (self, event):
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
      log.debug("============= CONNECTION SOURCE INFO =============")
      log.debug("this is the source IP (protosrc): " + str(a.protosrc))
      log.debug("this is the MAC adress (hwsrc): " + str(a.hwsrc))
      log.debug("this is the destination IP (protodst): " + str(a.protodst))
      log.debug("this is the port: " + str(inport))
      log.debug("============= CONNECTION SOURCE INFO =============")

      macToSend = None
      # TODO: ask if this is a reasonable way of doing things!
      # this handles figuring out where the MAC address to send to is
      if str(a.hwsrc) == "00:00:00:00:00:05" or str(a.hwsrc) == "00:00:00:00:00:06":
        # if the message came from h5 or h6, then use the hardcoded table to find where the 
        log.debug("a.protodst is...." + str(a.protodst))
        macToSend = self.hardcodeDictionary[str(a.protodst)]
        log.debug("the mac to send to is... " + str(macToSend))
      else:
        # TODO: Add a method that prevents if the arp is sent quickly before it can respond. It can sometimes be assigned to *BOTH* h5 and h6
        # now do round robin!
        if str(a.protosrc) in self.connectionTable:
          connectedHost = self.connectionTable[str(a.protosrc)]
          log.debug("connectedhost is...." + connectedHost)
          macToSend = self.hardcodeDictionary[connectedHost]
        else:
          if self.roundRobinSendToH5:
            macToSend = EthAddr("00:00:00:00:00:05")
            self.connectionTable["10.0.0.5"] = str(a.protosrc)
            self.connectionTable[str(a.protosrc)] = "10.0.0.5"
            self.roundRobinSendToH5 = False
          else:
            macToSend = EthAddr("00:00:00:00:00:06")
            self.connectionTable["10.0.0.6"] = str(a.protosrc)
            self.connectionTable[str(a.protosrc)] = "10.0.0.6"
            self.roundRobinSendToH5 = True
          # add the source's IP address to the table to it's related MAC address
          self.hardcodeDictionary[str(a.protosrc)] = a.hwsrc

      #add to the port table
      self.portTable[str(a.protosrc)] = inport

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
      r.hwsrc = macToSend
      e = ethernet(type=packet.type, src=event.connection.eth_addr,
      dst=a.hwsrc)
      e.payload = r
      if packet.type == ethernet.VLAN_TYPE:
        v_rcv = packet.find('vlan')
        e.payload = vlan(eth_type = e.type,
                                  payload = e.payload,
                                  id = v_rcv.id,
                                  pcp = v_rcv.pcp)
        e.type = ethernet.VLAN_TYPE
      msg = of.ofp_packet_out()
      msg.data = e.pack()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
      msg.in_port = inport
      event.connection.send(msg)


      if str(a.hwsrc) == "00:00:00:00:00:05" or str(a.hwsrc) == "00:00:00:00:00:06":
        # server to client 
        flowRules = of.ofp_flow_mod()
        flowRules.match.inport = inport
        flowRules.match.dl_type = pkt.ethernet.IP_TYPE
        flowRules.match.nw_dst = a.protodst
        
        actualIpDest = self.connectionTable[str(a.protosrc)]
        actualPortDest = self.portTable[actualIpDest]
        flowRules.actions.append(of.ofp_action_nw_addr.set_src(IPAddr("10.0.0.10")))
        flowRules.actions.append(of.ofp_action_output(port=actualPortDest))
        log.debug("============= LINKING INFO =============")
        log.debug("Will be sent to IP: " + actualIpDest)
        log.debug("Will be sent to MAC ADDRESS: " + str(macToSend))
        log.debug("Will be sent to port: " + str(actualPortDest))
        log.debug("============= LINKING INFO =============")
      else:
        # this is the client-side flow rules
        flowRules = of.ofp_flow_mod()
        flowRules.match.inport = inport
        flowRules.match.dl_type = pkt.ethernet.IP_TYPE
        flowRules.match.nw_dst = IPAddr("10.0.0.10")
        
        actualIpDest = self.connectionTable[str(a.protosrc)]
        actualPortDest = self.portTable[actualIpDest]
        flowRules.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(actualIpDest)))
        flowRules.actions.append(of.ofp_action_dl_addr.set_dst(macToSend))
        flowRules.actions.append(of.ofp_action_output(port=actualPortDest))
        log.debug("============= LINKING INFO =============")
        log.debug("Will be sent to IP: " + actualIpDest)
        log.debug("Will be sent to MAC ADDRESS: " + str(macToSend))
        log.debug("Will be sent to port: " + str(actualPortDest))
        log.debug("============= LINKING INFO =============")
      event.connection.send(flowRules)

    #this is the race condition prevention 
    elif packet.type == pkt.ethernet.IP_TYPE:
      packetMsg = of.ofp_packet_out()
      packetMsg.data = event.ofp
      packetMsg.actions.append(of.ofp_action_output(port=of.OFPP_TABLE))
      event.connection.send(packetMsg)

  # tcpdump -n -i h1-eth0
