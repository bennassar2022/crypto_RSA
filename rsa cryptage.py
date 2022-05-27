# -*- coding: cp1252 -*-
# système RSA, voir https://fr.wikipedia.org/wiki/Chiffrement_RSA
from random import randint,randrange
from sys import exit


def Chiffre(m=4,clefpublique=(3,33)):
    """Chiffre (nombre, clef publique =(e,n))
    où n est
    où e est
    exemple: Chiffre(1234567890987654321,(3,33))

    (m**e)%n est un calcul (trés) long, on se sert de la fonction pow qui est plus rapide
    le résultat d'une exponontiation modulaire est effectué par cette fonction sans
    calculer m**e (trés grand nombre)
    ceci est expliqué avec ce lien https://fr.wikipedia.org/wiki/Exponentiation_modulaire
    """
    e,n=clefpublique
    #contrôle non demandé
    if len(hex(m))>len(hex(n)):
        print "le nombre m est trop grand et ne peut être Chiffré"
        print "m = ",hex(m),"=",m,"\nn (clé de chiffrement) = ",hex(n)
        exit()
    #fin du contrôle
    return pow(m,e,n)



def Dechiffre(z=31,clefprivee=(7,33)):
    #return (z**d)%n remplacé par pow(z,d,n)
    d,n=clefprivee
    return pow(z,d,n)

# génération des clés
"""
trouver deux nombres premiers :
étant donné la taille des nombres pour le RSA, il faut utiliser l'algorithme
de Miller Rabin
ici , on utilise une méthode plus simple mais non adaptée à la taille des nombres
habituellement utilisés
EstPremier va planter si le nombre est trop grand
la taille de la boucle for est limitée à 2**25 environ selon la mémoire disponible
2**25 = 33 554 432
def nop(): #comme en assembleur, nop=no operation
    return
for i in range(2**25):
    nop()
pas d erreur
for i in range(2**26):
    nop()
donne
Traceback (most recent call last):
  File "<pyshell#51>", line 1, in <module>
    for i in range(2**26):
MemoryError

"""
def EstPremier(n=8895):
    def maxi(n):
        for i in range (1,n):
            if i**2>n:
                return i
    m=maxi(n)
    for i in range(2,m+1):
        if n%i==0:
            return False
    return True

def EstPremier(n=33554432+1): #sans la boucle for, plus élégant
    i=2;
    while i**2<n:
        if n%i==0:
            return False
        i+=1
    return True

def GenererPremier(n=20):
    m=randint(2**(n-1),2**n)
    while not EstPremier(m):
        m=randint(2**(n-1),2**n)
    return m    
            
# algorithme d'Euclide 
def PGCD(n,m):
    # initialisation
    no=n;mo=m;reste=1
    # boucle de calcul 
    while reste!=0:
        reste=n%m ; n=m; m=reste; 
        if reste!=0:
            pgcd=reste #le pgcd sera egal au reste de la ligne précédant un reste nul
    return pgcd

# algorithme d'Euclide étendu
def CoeffBezout(n,m):
     # initialisation
    no=n;mo=m;r3=1;u3=0;v3=0
    # boucle de calcul
    r1,u1,a1,v1,b1=n,1,n,0,m; 
    r2,u2,a2,v2,b2=m,0,n,1,m;
    r3=r1%r2
    while r3>0:
        u=u3;v=v3;pgcd=r3
        r3,u3,a3,v3,b3=r1%r2,u1-(r1/r2)*u2,a1,v1-(r1/r2)*v2,b1;
        r1,u1,a1,v1,b1=r2,u2,a2,v2,b2
        r2,u2,a2,v2,b2=r3,u3,a3,v3,b3
    return pgcd,u,v

 

def InverseModulaire(a,b):
    pgcd,u,v=CoeffBezout(a,b)
    if pgcd==1:
        if u<0:
            return u+b
        else:
            return u
    else:
        return 0


#  Test de primalité probabiliste de Miller-Rabin   https://gist.github.com/Ayrx/5884790
# ================================================
def lpowmod(a, b, n):
    """exponentiation modulaire: calcule (a**b)%n"""
    r = 1
    while b>0:
        if b&1==0:
            b = b>>1
        else:
            r = (r*a)%n
            b = (b-1)>>1
        a = (a*a)%n
    return r

    """ceci est un test probabiliste de primalité
k=40 est le nombre d'itération du test, plus ce nombre est grand plus la probabilité d'un
résultat correct est grande, n=40 est un bon compromis

https://gist.github.com/Ayrx/5884790
"""

def millerRabin(n, k=40): #millerRabin remplace la procedure EstPremier
    # renvoi True si le nombre est premier, False sinon

    # Implementation uses the Miller-Rabin Primality Test
    # The optimal number of rounds for this test is 40
    # See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    # for justification

    # If number is even, it's a composite number

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in xrange(k):
        a = randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in xrange(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

#  Test de primalité probabiliste de Miller-Rabin (fin du test)
# ================================================


# Générateur de clés

def GenerateurCles(nbits=100):
    """https://fr.wikipedia.org/wiki/Chiffrement_RSA"""
    b=nbits
    a=randint(3,b//2)
    #print "b=",b,", a=",a,", p>",2**a,", q>",2**(b-a)
    p=4;q=4 #un nombre non premier pour initialiser la boucle while    
    while not millerRabin(p):
        p=randint(2**a,2**a+1000)
    while not millerRabin(q):
        q=randint(2**(b-a),2**(b-a)+1000)
    n=p*q #module de chiffrement
    phi=(p-1)*(q-1) #indicatrice d'Euler
    #recherche d'un nombre e premier avec phi
    e=randint(phi/10,phi/2)
    while PGCD(e,phi)!=1:
        e=randint(phi/3,phi/2)
    #ce nombre est premier donc premier avec phi 
    d=InverseModulaire(e,phi)
    return (e,n),(d,n)

    


# les fonctions hex2int et int2hex n'existent pas en python 2.7, je les traduit
def hex2int(texte):
    return int(texte,16)
def int2hex(n):
    if hex(n)[-1]=='L':
        return hex(n)[2:-1].upper()
    else:
        return hex(n)[2:].upper()
        
def char2hex(lettre):
    return hex(ord(lettre))[2:].upper()
def hex2char(hexa):
    return chr(int(hexa,16))

# question 3.1

def str2hex(texte):
    resultat=''
    for lettre in texte:
        resultat+=char2hex(lettre)
    return resultat
        

def hex2str(codehexa='4C6520444D206EB032206427696E666F20706F727465726120737572205253412E'):
    code=''; texte=''
    for caractere in codehexa:
        code+=caractere
        if len(code)==2:
            texte+=hex2char(code)
            code=''
    return texte



# remplissage
def Remplissage(codehexa='FF',t=9,p=True):
    longueur=t
    for i in range(1000):
        longueur=i*t
        if longueur>=len(codehexa):
            break
    if p:
        while len(codehexa)<longueur:
            codehexa='0'+codehexa
    else:
        while len(codehexa)<longueur:
            codehexa+='0'
    return codehexa




def Decoupe(texte,t):
    resultat=[]
    while len(texte)!=0:
        resultat.append(texte[:t])
        texte=texte[t:]
    return resultat



def Assemble(liste):
    resultat=''
    return resultat.join(liste)


# chiffrement d'un message

def Chiffrement_version0(Message,Clef_Publique):
    t=len(int2hex(Clef_Publique[1]))
    texte=Remplissage(str2hex(Message),t-1,p=True)
    liste=Decoupe(texte,t-1)
    #print 'longueur exposant de chiffrement en hexa =',t
    #print 'texte en hexa\n',texte
    #print 'decoupe texte\n',liste
    listeint=[]
    for bloc in liste:
        listeint.append(hex2int(bloc))
    #print 'conversion en décimal\n',listeint
    listecode=[]
    for nombre in listeint:
        listecode.append(Chiffre(nombre,Clef_Publique))
    #print 'codage avec la clé publique\n',listecode
    listecodehexa=[]
    for code in listecode:
        listecodehexa.append(int2hex(code))
    #print 'conversion en hexa\n',listecodehexa
    for item in enumerate(listecodehexa):
        indice=item[0]; codehexa=item[1] #pour la compréhension , pas indispensable
        listecodehexa[indice]=Remplissage(codehexa,t,True)
    #print 'remplissage avec des 0 si nécessaire\n',listecodehexa
    resultat=Assemble(listecodehexa)
    #print "resultat\n",resultat
    return resultat

def Chiffrement(Message,Clef_Publique): #procédure réécrite 
    t=len(int2hex(Clef_Publique[1]))
    texte=Remplissage(str2hex(Message),t-1,p=True)
    liste=Decoupe(texte,t-1)
    for bloc in enumerate(liste):
        liste[bloc[0]]=Remplissage(int2hex(Chiffre(hex2int(bloc[1]),Clef_Publique)),t,True)
    return Assemble(listecodehexa)
 


# Dechiffrement

def Dechiffrement(message,Clef_Privee):
    #print"Dechiffrement"
    texte=''
    t=len(int2hex(Clef_Privee[1]))
    #print 'longueur exposant de chiffrement en hexa =',t
    liste=Decoupe(message,t)
    for item in enumerate(liste):
        liste[item[0]]=hex2int(item[1])
    #print "liste en décimal\n", liste
    for item in enumerate(liste):
        liste[item[0]]=Dechiffre(item[1],Clef_Privee)
        print "decodage\n",liste
    for item in enumerate(liste):
        liste[item[0]]=int2hex(item[1])
    #print "conversion hexa\n",liste
    for item in enumerate(liste):
        print len(item[1]),item[1]
        liste[item[0]]=Remplissage(item[1],t-1,True)
        print len(item[1]),item[1]
    #print "complément 0\n",liste
    texte=Assemble(liste)
    #print 'concatenation\n',texte
    texte=hex2str(texte)
    #print 'traduction\n',texte
    return texte

def tests():

    print"Début du programme\n"
    print
    print "Test : CoeffBezout(120,23)"
    print CoeffBezout(120,23)
    print
    print "Test d'inverse modulaire: InverseModulaire(183263,1179720)"
    print InverseModulaire(183263,1179720)
    print
    print "Test de millerRabin sur quelques nombres"
    ListeDeNombresPremiers=(999999972233,999999972241,999999972281,999999972331,999999972409,999999972427,999999972451,999999972463,999999972469,999999972487,
    999999972493,999999972509,999999972523,999999972547,999999972563,999999972577,999999972611,999999972637,999999972649,999999972703,
    999999972731,999999972733,999999972761,999999972781,999999972791,999999972817,999999972859,999999972863,999999972911,999999972913,
    999999972929,999999972967,999999972971,999999972973,999999972997,999999973043,999999973079,999999973099,999999973121,999999973187,
    999999973201,999999973207,999999973249,999999973253)
    NombreErreur=0
    NombreDeTest=0
    for nombre in ListeDeNombresPremiers:
        NombreDeTest+=1
        if not millerRabin(nombre): 
            print "erreur du test sur un nombre premier",millerRabin(nombre),nombre
            NombreErreur+=1
            if NombreErreur>3:
                break
    print "test sur des nombres non premiers entre ",ListeDeNombresPremiers[0],"et",ListeDeNombresPremiers[-1]
    for nombre in range(ListeDeNombresPremiers[0],ListeDeNombresPremiers[-1]):
                        if nombre not in ListeDeNombresPremiers: #nombre n'est donc pas un nombre premier 
                            NombreDeTest+=1
                            if millerRabin(nombre): #le test affirme que le nombre est premier
                                print "erreur du test sur un nombre non premier",millerRabin(nombre),nombre
                                NombreErreur+=1
                                if NombreErreur>3:
                                    break
    print "conclusions: ",NombreDeTest,'tests effectués,',NombreErreur,'erreurs constatées'
                                

    #Génération des clés                    
    print "\nGénérateur de Clés"
    clefPublique,ClefPrivee=GenerateurCles(100)
    print "Clef publique"
    print "e=",clefPublique[0],'n=',clefPublique[1]
    print "e=",int2hex(clefPublique[0]),'n=',int2hex(clefPublique[1])
    print "Clef privée"
    print "e=",ClefPrivee[0],'n=',ClefPrivee[1]
    print "e=",int2hex(ClefPrivee[0]),'n=',int2hex(ClefPrivee[1])
    print "vérification:"
    print "Le chiffrage de 111222333444555 donne",
    codage= Chiffre(111222333444555,clefPublique)
    print codage
    print 'Le décodage donne',
    print Dechiffre(codage,ClefPrivee)


    # codage et décodage d'une phrase
    print "\nCodage d'une phrase en hexa"
    print """str2hex("Le DM n°2 d'info portera sur RSA.")"""
    print str2hex("Le DM n°2 d'info portera sur RSA.")
    print
    print "Décodage d'un nombre hexa"
    print "hex2str('4C6520444D206EB032206427696E666F20706F727465726120737572205253412E') ="
    print hex2str('4C6520444D206EB032206427696E666F20706F727465726120737572205253412E')
    print "hex2str('4C65206465757869656D65206578657263696365') = "
    print hex2str('4C65206465757869656D65206578657263696365')
    print
    print 'Fonction de remplissage'
    codehex= "4C65206465757869656D65206578657263696365"
    print codehex,'longueur = ',len(codehex)
    print "on remplit avec un multiple de 9"
    texte= Remplissage(codehex,t=9,p=False)
    print texte,'longueur = ',len(texte)
    print len(texte),"=",len(texte)//9,"*9"
    print
    print 'Fonction de découpe '
    print Decoupe(Remplissage('4C65206465757869656D65206578657263696365',9,False),9)
    print
    print 'Fonction Assemble'
    print Assemble(Decoupe(Remplissage('4C65206465757869656D65206578657263696365',9,False),9))
    exit()
    #Chiffrement d'un message
    print"""\nChiffrement de "Le DM n°2 d'info portera sur RSA." """
    print Chiffrement_version0("Le DM n°2 d'info portera sur RSA.",clefPublique)          
    print Chiffrement("Le DM n°2 d'info portera sur RSA.",clefPublique)
    print        
    print '\n\ndéchiffrement de',messagecoder

    exit()

tests()
    





 








