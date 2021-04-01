#!/usr/bin/env python
# by bl4de | github.com/bl4de | twitter.com/_bl4de | hackerone.com/bl4de
import socket
import sys
import os
import ssl
import threading

def usage():
    print ("IRC simple Python client ssl | by bl4de&kamakepar \n")
    print ("$ ./main.py USERNAME CHANNEL\n")
    print ("where: USERNAME - your username, CHANNEL - channel you'd like to join (eg. channelname or #channelname)")


def channel(channel):
    if channel.startswith("#") == False:
        return "#" + channel
    return channel

def quit():
    client.send_cmd("QUIT", "Good bye!")
    print ("Quitting ...")
    exit(0)

class IRCSimpleClient:

    def __init__(self, username, channel, server="irc.hackint.org", port=6697):
        self.username = username
        self.server = server
        self.port = port
        self.channel = channel

    def connect(self):
        context = ssl.create_default_context()
        self.conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),server_hostname="irc.hackint.org")
        self.conn.connect((self.server, self.port))

    def get_response(self):
        return self.conn.recv(512).decode()

    def send_cmd(self, cmd, message):
        command = "{} {}\r\n".format(cmd, message).encode()
        self.conn.send(command)

    def send_message_to_channel(self, message):
        command = "PRIVMSG {}".format(self.channel)
        message = ":" + message
        self.send_cmd(command, message)

    def join_channel(self):
        cmd = "JOIN"
        channel = self.channel
        self.send_cmd(cmd, channel)

    def print_response(self):
        resp = self.get_response()
        if resp:
            msg = resp.strip().split(":")
            print ("\n< {}> {}".format(msg[1].split("!")[0], msg[2].strip())); os.system('echo "<'+msg[1].split("!")[0]+'>'+str(msg[2]).strip().replace('"', '/')+'">>history.txt'); 
            if 'start attack at' in str(msg[2]):
              pol = str(msg[2].strip()).split('start attack at')
              self.send_message_to_channel('Ok, Starting attack at '+pol[1].replace('?',''))
							

if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()
        exit(0)
    else:
        username = sys.argv[1]
        channel = channel(sys.argv[2])

    cmd = ""
    joined = False
    client = IRCSimpleClient(username, channel)
    client.connect()

    while(joined == False):
        resp = client.get_response()
        print(resp.strip())
        if "No Ident response" in resp:
            client.send_cmd("NICK", username)
            client.send_cmd(
                "USER", "{} * * :{}".format(username, username))

        # we're accepted, now let's join the channel!
        if "376" in resp:
            #client.send_cmd("NickServ VERIFY REGISTER"," hack1ing jpaphlltqouq")
            client.join_channel()

        # username already in use? try to use username with _
        if "433" in resp:
            username = "_" + username
            client.send_cmd("NICK", username)
            client.send_cmd(
                "USER", "{} * * :{}".format(username, username))
        

        # if PING send PONG with name of the server
        if "PING" in resp:
            client.send_cmd("PONG", ":" + resp.split(":")[1])

        # we've joined
        if "366" in resp:
            joined = True
            t = threading.Thread(target=client.print_response)
            t.start()
    try:
        while(cmd != "/quit"):
            cmd = input("< {}> ".format(username)).strip()
            if cmd == "/quit":
                quit()
            elif cmd == "/ping":
                client.send_cmd("PONG", ":" + resp.split(":")[1])
            if cmd and len(cmd) > 0:
                client.send_message_to_channel(cmd)
    except KeyboardInterrupt:
        quit()
        
        t = threading.Thread(target=client.print_response)
        t.start()
        