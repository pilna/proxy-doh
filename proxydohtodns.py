# -*- coding: utf-8 -*-
from __future__ import with_statement
from re import sub
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
from base64 import b64decode
from struct import pack, unpack


def bin(n):
    """
    conversion d'un entier 10 en base 2 et conversion en chaine de caractères.

    paramètre:
        n (int): un nombre appartenant à l'espace des entiers relatifs

    return:
        str: la représentation du nombre n en base 2 
    """
    digs = []
    s = None
    if n < 0:
        s = '-'
        n = abs(n)

    while n != 0:
        digs.append(str(n % 2))
        n /= 2

    if s:
        digs.append(s)
    digs.reverse()
    return ''.join(digs)


class ServerTcp:

    def __init__(self, adress="127.0.0.1", port=8888):
        """
        parameter:
            adress (str): l'adresse de notre serveur, si non specifié prend localhost par défaut
            port (int): le port de notre serveur, si non specifié prend le port 8888 par défaut
        """
        self.adress = adress
        self.port = port

    def run(self, verbose=True):
        """
        boucle principale de notre serveur

        parameter:
            verbose (bool): indique si on souhaite afficher des informations de connection au server
        """
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((self.adress, self.port))
        sock.listen(5)

        if verbose:
            print("Server is Listening on %s:%d" % (self.adress, self.port))
        while True:
            conn, addr = sock.accept()

            if verbose:
                print("Connected %s" % str(addr))

            data = conn.recv(1024)
            response = self.handleRequest(data)
            conn.sendall(response)
            conn.close()

    def handleRequest(self, data):
        """
        fonction prenant en charge les données envoyées par le client

        return:
            str: la réponse à envoyer au client
        """
        return data


class HTTPRequest:

    def __init__(self, method, path, arguments, httpVersion=1.0):
        """
        parameter:
            method (str): la méthode de la requête http (GET, POST, ...)
            path (str): le chemin de la requête tout ce qui ce trouve avant les arguments
            argument (dict[str, str]): dictionnaire des arguments
                example de path, argument:
                    dans la requête suivante:
                    /dnsRequest?dns=aaaa&priority=1
                    le path sera /dnsRequest 
                    et les arguments seront dns=aaaa et priority=1
            httpVersion (float): la version http de la requ$ete, si non precisée prend la version 1.0 par défaut
        """
        self.method = method
        self.path = path
        self.arguments = arguments
        self.httpVersion = httpVersion

    @classmethod
    def getFromString(cls, string):
        """
        fonction permettant d'obtenir un objet HTTPRequest à partir d'une string modélisant une requête http

        parameter:
            string (str): string modélisant la requête http

        return:
            (HTTPRequest): l'objet HTTPRequest crée à partir de la string
        """
        lines = string.split("\n")
        method, url, httpVersion = lines[0].split(" ")
        httpVersion = float(httpVersion.split("/")[1])

        url = url.split("?", 1)
        if len(url) == 2:
            path, args = url
            arguments = {}
            for arg in args.split("&"):
                nameOfVar, value = arg.split("=", 1)
                arguments[nameOfVar] = value

        return cls(method, path, arguments, httpVersion)

    def __str__(self):
        """
        méthode qui cast notre requête http en string

        return:
            (str): la requête http encoder dans une string
        """
        return "method : %s\nurl : %s\nversion http: %f" % (self.method, self.url, self.httpVersion)


class HTTPResponse:
    # les different type de reponse et leur id
    response = {
        200: "OK",
        400: "Bad Request",
        404: "Not Found",
        501: "Not Implemented",
    }

    def __init__(self, status, headers={}, content="", httpVersion=1.0):
        """
        parameter:
            status (int): le status de la reponse (doit etre contenu dans le dictionnaire HTTPResponse.response)
            header (dict[str, str]): un dictionnaire contenant les headers de la requete, si non precisé header vide
            content (str): le contenu de la réponse http, si non precisé vide
            httpVersion (float): la version http de la requete, si non precisée prend la version 1.0 par defaut
        """
        self.httpVersion = httpVersion
        self.status = status
        self.headers = headers
        self.content = content

    def responseLine(self):
        """
        method qui formate la première ligne de la réponse http

        return:
            (str): la première ligne de la reponse http encodée dans une string
        """
        return "HTTP/%.1f %d %s\n" % (self.httpVersion, self.status, HTTPResponse.response[self.status])

    def responseHeader(self):
        """
        method qui formate le header de la reponse http

        return:
            (str): le header encodé dans une string
        """
        output = ""

        for header, value in self.headers.items():
            output += "%s: %s\n" % (header, str(value))

        return output

    def responseContent(self):
        """
        method qui formate le contenu de la reponse http

        return:
            (str): le contenu encodé dans une string
        """
        return "%s" % str(self.content)

    def __str__(self):
        """
        fonction de cast de la reponse http en string

        return:
            (string): la reponse http encodée dans une string
        """
        return self.responseLine() + self.responseHeader() + "\n" + self.responseContent()


class DnsFormat:
    numberOfType = {
        "A": 1,
        "NS": 2,
        "MX": 15,
        "SOA": 6,
    }
    typeOfNumber = {
        1: 'A',
        2: "NS",
        15: "MX",
        6: "SOA",
    }
    # les different type de classe liee a leur id
    numberOfClass = {
        "IN": 1,
    }
    classOfNumber = {
        1: "IN",
    }

    def constructName(self, domain):
        """
        retourne l'encodage d'un nom de domaine en bytes selon le protocol dns

        parameter:
            domain (str): le nom de domain à encoder

        return:
            (str): le nom de domaine encodé dans une string
        """
        name = ""

        for subname in domain.split("."):
            name += pack("B", len(subname))
            for char in subname:
                name += pack("c", char)
        name += pack("B", 0)

        return name

    @staticmethod
    def getName(string):
        """
        fonction permettant de decoder une suites de byte en nom de domaine selon le protocol dns
        parameter:
            string (str): suites de bytes a decoder

        return:
            name (str): le nom de domaine
            string (str): le reste de la chaine qui n'a pas été decodé
        """
        p = 0
        save = 0
        name = ""
        l = 1

        while l:
            l = unpack("B", string[p])[0]
            if l >= 192:
                if save == 0:
                    save = p
                p = (l - 192) * 256 + (unpack("B", string[p+1])[0])
                l = unpack("B", string[p])[0]
            if len(name) and l:
                name += '.'
            p += 1
            name += "".join(unpack("c" * l, string[p:(p+l)]))
            p += l
        if save > 0:
            p = save + 2

        return name, string[p:]


class DnsQuestion(DnsFormat):

    def __init__(self, domain, typ, classe):
        """
        parameter:
            domain (str): le nom de domaine ou l'ip
            typ: le type de la question (A, MX, NS, ...)
            classe: la classe de la question
        """
        self.domain = domain
        self.typ = typ
        self.classe = classe

    @classmethod
    def fromString(cls, string):
        """
        fonction permettant d'obtenir un objet DnsQuestion à partir d'une string modélisant une question dns

        parameter:
            string (str): string modélisant la question

        return:
            (DnsQuestion): la question Dns générée à partir de la string passée en paramètre
        """
        domain, temp = DnsFormat.getName(string)
        temp = unpack(">HH", temp)
        typ, classe = DnsFormat.typeOfNumber[temp[0]], DnsFormat.classOfNumber[temp[1]]
        return DnsQuestion(domain, typ, classe), temp

    def __str__(self):
        """
        fonction permettant de convertir notre DnsQuestion en string

        return:
            (string): la DnsQuestion encodée dans une string
        """
        question = self.constructName(self.domain)
        question += pack(">H", self.numberOfType[self.typ])
        question += pack(">H", self.numberOfClass[self.classe])
        return question


class DnsAnswer(DnsFormat):

    def __init__(self, domain, typ, RData, timeToLive=0, classe='IN'):
        """
        parameter:
            domain (str): le nom de domaine ou l'ip
            typ (str): le type de l'answer (A, MX, NS, ...)
            RData (str): la data de l'answer
            timeToLive (int): la durée de vie en cache, si non precisée 0
            classe: la classe de la réponse, si non precisée IN 
        """
        self.domain = domain
        self.typ = typ
        self.RData = RData
        self.timeToLive = timeToLive
        self.classe = classe

    def buildAnswerTypeA(self):
        """
        fonction retournant le cast du Rdata et du Rdlength d'un type A

        return:
            (str): le Rlength et le Rdata encodés
        """
        output = ""
        output += pack(">H", 4)

        for number in self.RData.split("."):
            output += pack('B', int(number))

        return output

    def buildAnswerTypeNS(self):
        """
        fonction retournant le cast du Rdata et du Rdlength d'un type NS

        return:
            (str): le Rlength et le Rdata encodés
        """
        output = ""
        length = 1

        for subdomain in self.RData.split("."):
            length += 1 + len(subdomain)

        output += pack(">H", length)
        output += self.constructName(self.RData)
        return output

    def buildAnswerTypeMX(self):
        """
        fonction retournant le cast du Rdata et du Rdlength d'un type MX

        return:
            (str): le Rlength et le Rdata encodés
        """
        output = ""
        length = 3
        priority, domain = self.RData.split(" ")

        for subdomain in domain.split("."):
            length += 1 + len(subdomain)

        output += pack(">H", length)
        output += pack(">H", int(priority))
        output += self.constructName(domain)

        return output

    def __str__(self):
        """
        fonction permettant de convertir notre DnsAnswer en string

        return:
            (str): la DnsAnswer encodée dans une string
        """
        answer = str(DnsQuestion(self.domain, self.typ, self.classe))
        answer += pack(">I", self.timeToLive)

        if self.typ == 'A':
            answer += self.buildAnswerTypeA()
        elif self.typ == "NS":
            answer += self.buildAnswerTypeNS()
        elif self.typ == "MX":
            answer += self.buildAnswerTypeMX()
        else:
            raise TypeError("type %s doesn't support" % self.typ)

        return answer


class DnsHeader(DnsFormat):

    def __init__(self, headerID=1, qr=0, opcode=0, AA=False, TC=False, RD=False, RA=False, Z=0, Rcode=0, QDcount=0, ANcount=0, NScount=0, ARcount=0):
        """
        parameter:
            headerID (int): l'id du header, si non precisée 1
            qr (int): 0 si c'est une question 1 si c'est une réponse, si non precisée 0
            opcode (int): l'op code du header, si non precisé 0
            AA (bool): Authoritative answer, si non precisée False
            TC (bool): truncated answer, si non precisée False
            RD (bool): recursion desired, si non precisée False
            RA (bool): recursion available, si non precisée False
            Z (int): Zero, si non precisé 0
            Rcode (int): rcode header, si non precisé 0 (No Error)
            QDcount (int): nombre de question, si non precisé 0
            ANcount (int): nombre d'answer, si non precisé 0
            NScount (int): nombre d'authorite, si non precisé 0
            ARcount (int): nombre d'information additionnel, si non precisé 0
        """
        self.headerID = headerID
        self.qr = qr
        self.opcode = opcode
        self.AA = AA
        self.TC = TC
        self.RD = RD
        self.RA = RA
        self.Z = Z
        self.Rcode = Rcode
        self.QDcount = QDcount
        self.ANcount = ANcount
        self.NScount = NScount
        self.ARcount = ARcount

    @classmethod
    def fromString(cls, string):
        """
        fonction permettant d'obtenir un objet DnsHeader à partir d'une string modélisant un header dns

        parameter:
            string (str): string modélisant le header

        return:
            (DnsHeader): le header Dns généré à partir de la string
        """
        header = unpack(">HBBHHHH", string[:12])
        headerID = header[0]
        temp = bin(header[1]).zfill(8)
        qr, opcode, aa, tc, rd = temp[0], temp[1:5], temp[5], temp[6], temp[7]
        temp = bin(header[2]).zfill(8)
        ra, z, rcode = temp[0], temp[1:4], temp[-4:]
        QDcount = header[3]
        ANcount = header[4]
        NScount = header[5]
        ARcount = header[6]
        return DnsHeader(headerID, qr, opcode, aa, tc, rd, ra, z, rcode, QDcount, ANcount, NScount, ARcount), string[12:]

    def __str__(self):
        """
        fonction permettant de convertir notre DnsHeader en string

        return:
            (str): le DnsHeader encodé dans une string
        """
        header = ""
        header += pack(">H", self.headerID)
        header += pack("B", int(bin(int(self.qr)).zfill(1) + bin(int(self.opcode)).zfill(4) + bin(
            int(self.AA)).zfill(1) + bin(int(self.TC)).zfill(1) + bin(int(self.RD)).zfill(1), 2))
        header += pack("B", int(bin(int(self.RA)).zfill(1) +
                                bin(int(self.Z)).zfill(3) + bin(int(self.Rcode)).zfill(4), 2))
        header += pack(">H", self.QDcount)
        header += pack(">H", self.ANcount)
        header += pack(">H", self.NScount)
        header += pack(">H", self.ARcount)
        return header


class DnsResponse:

    def __init__(self, questions=[], answers=[], authoritys=[], additionnals=[], requestID=1):
        """
        parameter:
            requestID (int): l'id de la réponse, si non precisé 1 par défaut
            questions (List[DnsQuestion]): liste des questions
            answers (List[DnsAnswer]): liste des answers
            authoritys (List[DnsAnswer]): liste des authoritees
            additinnals (List[DnsAnswer]): liste des contenus additionnels
        """
        self.requestID = requestID
        self.questions = questions
        self.answers = answers
        self.authoritys = authoritys
        self.additionnals = additionnals

    def __str__(self):
        """
        fonction permettant de convertir notre DnsResponse en string

        return:
            (string): la DnsResponse encodée dans une string (non compressée)
        """
        response = str(DnsHeader(self.requestID, qr=1, QDcount=len(self.questions), ANcount=len(
            self.answers), NScount=len(self.authoritys), ARcount=len(self.additionnals)))

        for question in self.questions:
            response += str(question)

        for answer in self.answers:
            response += str(answer)

        for additionnal in self.additionnals:
            response += str(additionnal)

        return response


class DnsRequest:

    def __init__(self, header, questions=[]):
        """
        parameters:
            header (DnsHeader): les headers de la requête
            questions (List[DnsQuestion]): les questions de la requpête
        """
        self.header = header
        self.questions = questions

    @classmethod
    def fromString(cls, string):
        """
        fonction permettant d'obtenir un objet DnsRequest à partir d'une string modélisant une request dns

        parameter:
            string (str): string modélisant le header

        return:
            (DnsRequest): la requête Dns générée à partir de la string
        """
        header, string = DnsHeader.fromString(string)
        questions = []

        for i in range(header.QDcount):
            question, string = DnsQuestion.fromString(string)
            questions.append(question)

        return DnsRequest(header, questions)

    def __str__(self):
        """
        fonction permettant de convertir notre DnsRequest en string

        return:
            (string): la DnsRequest encodée dans une string
        """
        output = str(self.header)

        for question in self.questions:
            output += str(question)

        return output


class ServerDoH(ServerTcp):
    requestID = 0 # unique

    def __init__(self, adress='127.0.0.1', resolverAdress="1.2.3.4", port=80):
        """
        parameter:
            adress (str): l'adresse de notre serveur, si non specifiée prend localhost par défaut
            resolverAdress (str): l'adresse de notre resolver dns, si non specifiée prend 1.2.3.4 par défaut
            port (int): le port de notre serveur, si non specifié prend le port 80 par défaut
        """
        ServerTcp.__init__(self, adress=adress, port=port)
        self.resolverAdress = resolverAdress

    def serveRequestID(self):
        """
        méthode permettant d'obtenir un id unique de requestDns

        return:
            int: unique id
        """
        ServerDoH.requestID += 1
        # si l'id depasse la taille maximal alors elle repart a 0
        ServerDoH.requestID %= 65535
        return ServerDoH.requestID

    def handleRequest(self, data):
        """
        fonction permettant de gérer l'obtention d'une requete http

        return:
            (str): la réponse du handler
        """
        request = HTTPRequest.getFromString(data)

        try:
            handler = getattr(self, "handle%s" % request.method.capitalize())
        except:
            handler = self.handleNotImplemented

        return handler(request)

    def handleGet(self, request):
        """
        fonction permettant de gérer les requête GET

        return:
            (str): la réponse du get
        """
        if request.path == '/':
            response = self.handleDnsRequest(request)
        else:
            response = self.handle404(request)

        return str(response)

    def handle404(self, request):
        """
        fonction gérant les erreurs 404

        return:
            HTTPResponse: une réponse 404  
        """
        return HTTPResponse(404, httpVersion=request.httpVersion)

    def handleNotImplemented(self, request):
        """
        fonction gérant les erreurs 501

        return:
            HTTPResponse: une réponse 501
        """
        return HTTPResponse(501, httpVersion=request.httpVersion)

    def sendToDnsResolver(self, request):
        """
        fonction permettant d'envoyer une requête dns au resolver

        return:
            str: la réponse du dns
        """
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.sendto(request, (self.resolverAdress, 53))
        response, _ = sock.recvfrom(4096)
        return response

    def getAdditionnal(self, dnsQuestion):
        """
        fonction retournant toutes les reponses se situant dans le cache à une question dns

        parameter:
            (DnsQuestion): la question dns

        return:
            List[DnsAnswer]: les réponses à la question qui se situe dans le cache
        """
        additionnals = []

        with open("../etc/bind/db.static", 'r') as cache:
            for line in cache.readlines():
                line = sub(" +", " ", line.replace("\t", " ").replace("\n", "")).split(" ")
                if len(line) == 5:
                    domain, classe, typ, priority, rdata = line
                    answer = DnsAnswer(domain, typ,  " ".join([priority, rdata]), classe=classe)
                else:
                    domain, classe, typ, rdata = line
                    answer = DnsAnswer(domain, typ, rdata, classe=classe)

                if dnsQuestion.domain == answer.domain and dnsQuestion.typ == answer.typ and dnsQuestion.classe == answer.classe:
                    additionnals.append(answer)

        return additionnals

    def cacheAnswer(self, dnsRequest):
        """
        fonction retournant la réponse à la requête dns passée en paramètre si la réponse se situe dans le cache

        parameter:
            (DnsRequest): la requête dns

        return:
            DnsReponse: si la réponse de la requête a eté trouvé dans le cache
            None: si la réponse n'as pas été trouvé dans le cache 
        """
        answers = []
        additionnals = []
        questions = dnsRequest.questions

        with open("../etc/bind/db.static", 'r') as cache:
            for line in cache.readlines():
                line = sub(" +", " ", line.replace("\t"," ").replace("\n", "")).split(" ")
                if len(line) == 5:
                    domain, classe, typ, priority, rdata = line
                    answer = DnsAnswer(domain, typ,  " ".join([priority, rdata]), classe=classe)
                else:
                    domain, classe, typ, rdata = line
                    answer = DnsAnswer(domain, typ, rdata, classe=classe)

                for question in questions:
                    if question.domain == answer.domain and question.typ == answer.typ and question.classe == answer.classe:
                        answers.append(answer)
                        if question.typ in ['MX', 'NS']:
                            additionnals += self.getAdditionnal(
                                DnsQuestion(answer.RData.split(" ")[1], 'A', 'IN'))

        return DnsResponse(questions, answers, additionnals=additionnals) if answers else None

    def handleDnsRequest(self, request):
        """
        fonction gérant la demande d'une requête dns

        return:
            (HTTPResponse): la réponse dns contenue dans la reponse http
        """
        if "dns" not in request.arguments:
            return HTTPResponse(400, httpVersion=request.httpVersion)

        decodeRequest = b64decode(request.arguments["dns"], altchars="-_")
        dnsRequest = DnsRequest.fromString(decodeRequest)
        cacheAnswer = self.cacheAnswer(dnsRequest)

        if cacheAnswer:
            header = {
                "Content-Type": "application/dns-message",
                "Content-Length": len(str(cacheAnswer)),
            }
            return HTTPResponse(200, header, str(cacheAnswer))

        dnsRequest.header.headerID += self.serveRequestID()
        response = self.sendToDnsResolver(str(dnsRequest))

        header = {
            "Content-Type": "application/dns-message",
            "Content-Length": len(response),
        }

        return HTTPResponse(200, header, response)


if __name__ == "__main__":
    ServerDoH("1.2.3.54", "1.2.3.4", 80).run()
