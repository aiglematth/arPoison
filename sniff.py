"""
But    --> Fichier contenant les outils en rapport avec le sniff
Auteur --> Aiglematth
"""
#Zone d'import des modules
from scapy.all import *
from colorama import Fore, Style
from threading import Thread
#############################
class Sniff():
    """
    Classe contenant tout les types de sniffs disponibles
    """
    def __init__(self):
        """
        Constructeur
        """
        self.red = Fore.RED
        self.resetAll = Style.RESET_ALL
        #############################
        self.time_out = 10
        self.counter = 0
        self.fileTo = None
        self.summary = True
        #############################
        self.filtre = ""
        self.typeOfPacket = []
        self.src = []
        self.dst = []
        self.port = []
        self.resultat = []
        #############################
    #LES ENREGISTREURS
    def enregistrer(self, pkt, fileTo):
        """
        Enregistreur pour les filtres
        """
        with open(fileTo, "a") as file:
            if self.summary == False:
                file.write(pkt.show(dump=True) + "\n\n")
            else:
                file.write(pkt.summary() + "\n\n")

    def enregistrerSelf(self, fileTo, summary=True):
        """
        Enregistrer tout le self dans un fichier
        """
        with open(fileTo, "a") as file:
            if self.summary == False:
                for pkt in self.resultat:
                    file.write(pkt.show(dump=True) + "\n\n")
            else:
                for pkt in self.resultat:
                    file.write(pkt.summary() + "\n\n")

    def enregistrerAvecOptions(self, fileTo, summary=True, types=[TCP, UDP], ips=["127.0.0.1"]):
        """
        Enregistrer des paquets dans un fichier en fonction de filtres
        """
        pasfin = []
        vu = []
        for paquet in self.resultat:
            try:
                if paquet.payload.src in ips or paquet.payload.dst in ips:
                    pasfin.append(paquet)
            except:
                if paquet.payload.psrc in ips or paquet.payload.pdst in ips:
                    pasfin.append(paquet)
        for p in pasfin:
            if p not in vu:
                vu.append(p)
                for type in types:
                    try:
                        p[type.upper()]
                        with open(fileTo, "a") as file:
                            if summary == False:
                                file.write(p.show(dump=True) + "\n\n")
                            else:
                                file.write(p.summary() + "\n\n")
                    except:
                        pass

    def enregistrerTypes(self, fileTo, summary, types):
        vu = []
        for paquet in self.resultat:
            for type in types:
                try:
                    if paquet not in vu:
                        paquet[type.upper()]
                        with open(fileTo, "a") as file:
                            if summary == False:
                                file.write(paquet.show(dump=True) + "\n\n")
                            else:
                                file.write(paquet.summary() + "\n\n")
                    else:
                        vu.append(paquet)
                except:
                    vu.append(paquet)

    def enregistrerIps(self, fileTo, summary, ips):
        for paquet in self.resultat:
            try:
                if (paquet.payload.src in ips or paquet.payload.dst in ips):
                    with open(fileTo, "a") as file:
                        if summary == False:
                            file.write(paquet.show(dump=True) + "\n\n")
                        else:
                            file.write(paquet.summary() + "\n\n")
            except:
                if (paquet.payload.psrc in ips or paquet.payload.pdst in ips):
                    with open(fileTo, "a") as file:
                        if summary == False:
                            file.write(paquet.show(dump=True) + "\n\n")
                        else:
                            file.write(paquet.summary() + "\n\n")
    ################################################################################################
    #LES FILTRES
    def filtreIpTcpUdp(self, pkt, fileTo):
        """
        Filtre des protocoles ip et tcp / udp, ne sélectionne que les paquets dont les ip sources et les ports destinations/sources
        correspondent à des valeurs dans self.src et self.port
        """
        if pkt.payload.src in self.src and pkt.payload.dst in self.dst and (pkt.payload.payload.sport or pkt.payload.payload.dport) in self.port:
            if fileTo != None:
                self.enregistrer(pkt, fileTo)
            self.resultat.append(pkt)

    def filtreIp(self, pkt, fileTo):
        """
        Filtre du protocole ip, rajoute le paquet dans resultat si la src est dans self.src
        """
        if pkt.payload.src in self.src and pkt.payload.dst in self.dst:
            if fileTo != None:
                self.enregistrer(pkt, fileTo)
            self.resultat.append(pkt)

    def filtreArp(self, pkt, fileTo):
        """
        Filtre du protocole ip, rajoute le paquet dans resultat si la src est dans self.src
        """
        if pkt.payload.psrc in self.src and pkt.payload.pdst in self.dst:
            if fileTo != None:
                self.enregistrer(pkt, fileTo)
            self.resultat.append(pkt)

    def add(self, pkt, fileTo):
        self.resultat.append(pkt)
        if fileTo != None:
                self.enregistrer(pkt, fileTo)
    ################################################################################################
    #LA GROSSE FONCTION FILTRE
    def monFiltre(self, pkt):
        """
        Filtre des paquets
        """
        #SI ON A DEFINIT DES SOURCES ET DES PORTS
        if (self.port and self.src) != None:
            if pkt.payload.name.upper() == "IP" and pkt.payload.payload.name.upper() == ("TCP" or "UDP"):
                self.filtreIpTcpUdp(pkt, self.fileTo)
        #SI ON A DEFINIT UNIQUEMENT DES SOURCES
        elif self.port == None and self.src != None:
            if pkt.payload.name.upper() == "IP":
                self.filtreIp(pkt, self.fileTo)
            elif pkt.payload.name.upper() == "ARP":
                self.filtreArp(pkt, self.fileTo)
        #SINON ON RAJOUTE TOUT LES PAQUETS
        else:
            self.add(pkt, self.fileTo)
    ################################################################################################
    #LES SNIFFERS
    def mySniff(self, typeOfPacket=["IP", "TCP", "UDP"], src=["127.0.0.1"], dst=["127.0.0.1"], port=["80"], time_out=10, counter=0, fileTo=None, summary=True):
        """
        Un sniffer plutôt développé, on enregistre toutes les options pour pouvoir faire un reSniff simplement
        """
        self.typeOfPacket = typeOfPacket
        self.src = src
        self.dst = dst
        self.port = port
        self.time_out = time_out
        self.counter = counter
        self.fileTo = fileTo
        self.summary = summary

        if typeOfPacket != None:
            filtre = typeOfPacket.pop(0)
            for proto in typeOfPacket:
                filtre += " or {}".format(proto.lower())
        else:
            filtre = None
        self.filtre = filtre

        print(self.red + "### Début du sniff ###" + self.resetAll)
        sniff(prn=self.monFiltre, filter=filtre, count=counter, timeout=time_out)
        print(self.red + "\n### Fin du sniff ###" + self.resetAll)

    def sameSniff(self):
        """
        Effectue le même sniff que préceddement
        """
        sniff(prn=self.monFilter, filter=self.filtre, count=self.counter, timeout=self.time_out)
    ################################################################################################
    #LES SHOWS
    def showAll(self):
        for paquet in self.resultat:
            paquet.show()

    def showSpecialTypes(self, types):
        vu = []
        for paquet in self.resultat:
            for type in types:
                try:
                    if paquet not in vu:
                        paquet[type.upper()]
                        paquet.show()
                        vu.append(paquet)
                except:
                    pass

    def showSpecialIps(self, ips):
        for paquet in self.resultat:
            try:
                if (paquet.payload.src in ips or paquet.payload.dst in ips):
                    paquet.show()
            except:
                if (paquet.payload.psrc in ips or paquet.payload.pdst in ips):
                    paquet.show()

    def showSpecialIpsAndTypes(self, ips, types):
        pasfin = []
        vu = []
        for paquet in self.resultat:
            try:
                if (paquet.payload.src in ips or paquet.payload.dst in ips):
                    pasfin.append(paquet)
            except:
                if (paquet.payload.psrc in ips or paquet.payload.pdst in ips):
                    pasfin.append(paquet)
        for p in pasfin:
            for type in types:
                try:
                    if p not in vu:
                        p[type.upper()]
                        p.show()
                        vu.append(p)
                except:
                    vu.append(p)
    def clear(self):
        self.resultat = []

class ThreadSniff(Thread):
    """
    La classe qui permettra de créer un thread de sniff
    """
    def __init__(self, objet, typeOfPacket=None, src=None, dst=None, port=None, time_out=10, counter=0, fileTo=None, summary=True):
        """
        Constructeur de cette classe fille de Thread
        """
        Thread.__init__(self)

        self.objet = objet
        self.typeOfPacket = typeOfPacket
        self.src = src
        self.dst = dst
        self.port = port
        self.time_out = time_out
        self.counter = counter
        self.fileTo = fileTo
        self.summary = summary

    def run(self):
        """
        Surcharge de la méthode run
        """
        self.objet.mySniff(self.typeOfPacket, self.src, self.dst, self.port, self.time_out, self.counter, self.fileTo, self.summary)

if __name__ == "__main__":
    a = Sniff()
    t = ThreadSniff(a)
    t.start()
    t.join()
    a.showAll()
