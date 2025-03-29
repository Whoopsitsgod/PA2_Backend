# Max Donaldson's PA2 Assignment
# Last worked on: 3/29/2025
# arp_responder from POX (https://github.com/noxrepo/pox) helped directly for
# inspiration and used/referenced heavily within the development of this

from pox.core import core
import pox
log = core.getLogger()
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.vlan import vlan
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
 
def launch ():
  core.registerNew(MyComponent)

class MyComponent (object):
  def __init__ (self):
    core.openflow.addListeners(self)
    self.roundRobinSendToH5 = True
    #initialize hardcodeTable
    self.hardcodeDictionary = {}
    self.hardcodeDictionary["10.0.0.5"] = EthAddr("00:00:00:00:00:05")
    self.hardcodeDictionary["10.0.0.6"] = EthAddr("00:00:00:00:00:06")
    #initialize connectionTable
    self.connectionTable = {}
    #initialize portTable
    self.portTable = {}
    self.portTable["10.0.0.5"] = 5
    self.portTable["10.0.0.6"] = 6
    
 
  def _handle_ConnectionUp (self, event):
    fm = of.ofp_flow_mod()
    fm.priority -= 0x1000
    fm.match.dl_type = ethernet.ARP_TYPE
    fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    event.connection.send(fm)

  def _handle_PacketIn (self, event):
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed

    # check if packet parsed correctly
    if not packet.parsed:
      log.warning("%s: ignoring unparsed packet", dpid_to_str(dpid))
      return
    
    a = packet.find('arp')
    if packet.type == pkt.ethernet.ARP_TYPE:
      mac = event.connection.eth_addr
      # Connection debug help
      log.debug("============= CONNECTION SOURCE INFO =============")
      log.debug("this is the source IP (protosrc): " + str(a.protosrc))
      log.debug("this is the MAC adress (hwsrc): " + str(a.hwsrc))
      log.debug("this is the destination IP (protodst): " + str(a.protodst))
      log.debug("this is the port: " + str(inport))
      log.debug("============= CONNECTION SOURCE INFO =============")
      macToSend = None

      # this handles figuring out where the MAC address to send to is
      if str(a.hwsrc) == "00:00:00:00:00:05" or str(a.hwsrc) == "00:00:00:00:00:06":
        # if the message came from h5 or h6, then use the hardcoded table to find which MAC to send to
        macToSend = self.hardcodeDictionary[str(a.protodst)]
      else:
        # now do round robin!
        if str(a.protosrc) in self.connectionTable:
          # this aids if the ARP to be sent twice by accident, which via round robin could mean h1 -> h5 *and* h6
          connectedHost = self.connectionTable[str(a.protosrc)]
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

      #construct the arp_response
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
        flowRules.match.nw_src = a.protosrc
        
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
        flowRules.match.nw_src = a.protosrc
        
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

    elif packet.type == pkt.ethernet.IP_TYPE:
      packetMsg = of.ofp_packet_out()
      packetMsg.data = event.ofp
      packetMsg.actions.append(of.ofp_action_output(port=of.OFPP_TABLE))
      event.connection.send(packetMsg)
