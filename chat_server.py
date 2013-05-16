#am facut ceva research pe net despre sockets si threading
from socket import *
import thread
import time
 
HOST = "localhost"
PORT = 4004 #am cautat un port care sa fie cat de cat nefolosit :)

#din cate am vazut prin documentatie, cam astea sunt setarile default
#pentru o conexiune server/client
server = socket(AF_INET, SOCK_STREAM)
server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
server.setblocking(False)
server.bind((HOST, PORT))
server.listen(1)
print "Bogdan's Chatroom :: Listening on %s" % ("%s:%s" % server.getsockname())


 
def accept(conn):
#aici am avut multe incercari si mi-am dat seama ca daca nu chem functia
#pornind un thread, se blocheaza si nu face nimic

    def threaded():
        conn.send("Nume utilizator: ")
                   
        while True:
                       
            try:
                name = conn.recv(1024).strip() #input username pt chat
            except error:
                continue
            if name in users:
                conn.send("Numele deja exista!\n")
                conn.send("Nume utilizator: ")
            elif name:
                conn.setblocking(False)
                users[name] = conn
                broadcast(name, "----@@@@ %s s-a conectat la chatroom @@@@----" % name)
                break
    thread.start_new_thread(threaded, ())
 
def broadcast(name, message):
#aici fac broadcast din chatroom catre toti utilizatorii cu mesajul unuia dintre ei
    print message
    for to_name, conn in users.items():
        if to_name != name:
            try:
                conn.send(message + "\n")
            except error:
                pass
 
#Main
users = {} #dictionar pentru stocarea numelor de utilizator
while True:
    try:
        #accept orice conexiune inbound
        while True:
            try:
                conn, addr = server.accept()
            except error:
                break
            accept(conn)
        #citesc din stream-ul de date
        for name, conn in users.items():
            try:
                message = conn.recv(1024)
            except error:
                continue
            if not message:
                #din documentatie am inteles ca se trimite un empty string atunci cand conn.recv() nu primeste nimic
                #deci asta il consider event de disconnect si sterg utilizatorul
                del users[name]
                broadcast(name, "----==== %s a plecat din chatroom ====----" % name)
            else:
                broadcast(name, "%s> %s" % (name, message.strip()))
        time.sleep(.1) #aici daca nu pun un delay cat de mic, sta procesorul in 100%, cred ca e de la loop
    except (SystemExit, KeyboardInterrupt):
        break
