# my (Max Donaldson's) function
import pox.proto.arp_responder as arp_responder
from pox.core import core
import pox

def launch (**kw):
    print("this is a test, if this prints out; then it works!")
    newObby = ICantThinkOfAGoodName()

class ICantThinkOfAGoodName ():
    def __init__ (self):
        print("test")
        core.addListeners(self)

    def _handle_PacketIn (self, event):
        print("packet!")

    def _handle_GoingUpEvent (self, event):
        core.openflow.addListeners(self)
        print("another test, pray to lordy it works")
