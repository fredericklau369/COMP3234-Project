#!/usr/bin/python3

# Student name and No.: LAU Chun Lam (3035123851)
# Student name and No.: LO Wnag Kin (3035186401)
# Development platform: Ubuntu 14.04 LTS
# Python version: 3.6.0
# Version: Stage One Completed.

from tkinter import *
import sys
import socket
from time import sleep
from threading import Thread

#
# Global variables
#
joinedroom = False  # True if the user has join a chatroom
username = ""  # Store the registered username for joining the chatroom
sockfd = socket.socket()  # Create a socket object for connection
MSID = 0  # The hash value of all membership info
join_msg = ""  # Message being sent to server in order to join the chatroom
quit_req = False  # True if quit is requested
keep_alive_thd = None  # The keep alive thread


#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address),
# and str(Port) to form the input to this hash function
#
def sdbm_hash(instr):
    hash = 0
    for c in instr:
        hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
    return hash & 0xffffffffffffffff


#
# Functions to handle user input
#

def do_User():
    """Register username."""
    global username
    if not joinedroom:

        if len(userentry.get()) > 32:
            CmdWin.insert(
                1.0, "\n[Remind]Username is too long, please register "
                     "a name with less than 32 characters.")
        elif len(userentry.get()) == 0:
            CmdWin.insert(1.0, "\n[Remind]Username cannot be blank.")
        else:
            if username != "":
                outstr = "\n[User] New username: %s" +\
                         "\n[User] Old username: " + username
            else:
                outstr = "\n[User] username: %s"
            username = userentry.get()
            CmdWin.insert(1.0, outstr % username)
    else:
        CmdWin.insert(1.0, "\n[Remind]Name cannot be changed "
                      "since you have joined a chatroom."
                      "\n[Remind]Your current username: " + username)
    clear_input()


def do_List():
    """List all available chatrooms."""
    list_msg = "L::\r\n"
    send_msg(list_msg)
    try:
        resp_list = get_resp_list()
        # split the response message into a list of tokens
        if resp_list[0] == "G" and resp_list[1] == '':
            CmdWin.insert(1.0, "\nNo chatroom group")
        elif resp_list[0] == "F":
            CmdWin.insert(1.0, "\n[Error] ", resp_list[1])
        else:
            for chatroomName in resp_list[1:-2]:
                CmdWin.insert(1.0, "\n" + chatroomName)
            CmdWin.insert(1.0, "\nchatroom name")
    except socket.error as emsg:
        recv_err(emsg)


def do_Join():
    """Join a chatroom."""
    global joinedroom, join_msg
    if joinedroom:
        CmdWin.insert(
            1.0, "\n[Remind]Failed. You have already joined a chatroom group.")
    elif username == '':
        CmdWin.insert(
            1.0, "\nPlease input your username first, "
            "then press the [User] button")
    elif len(userentry.get()) == 0:
        CmdWin.insert(
            1.0, "\n[Remind]Please input the name of the room "
            "that you want to join")
    else:
        roomname = userentry.get()
        userIP, userPort = sockfd.getsockname()
        join_msg = "J:%s:%s:%s:%s::\r\n" %\
            (roomname, username, userIP, str(userPort))
        joinedroom = send_join_msg(roomname)
    clear_input()


def do_Send():
    """Send a message across the chatroom."""
    CmdWin.insert(1.0, "\nPress Send")


def do_Quit():
    """Quit the program."""
    global quit_req
    quit_req = True
    keep_alive_thd.join()
    sockfd.close()
    sys.exit(0)


def clear_input():
    """Clear the input box."""
    userentry.delete(0, END)


def send_msg(msg):
    """Send a message to server."""
    sockfd.send(msg.encode('ascii'))


def get_resp_list():
    """Return a list of responses from server."""
    rmsg = sockfd.recv(500)
    rmsg = rmsg.decode('ascii')
    if len(rmsg) == 0:
        print("Connection is broken. Exiting")
        sys.exit(1)
    return rmsg.split(':')


def recv_err(err):
    """Handle an error received."""
    print ("\nReceive error: " + err)


def send_join_msg(roomname=None):
    """Send a join message. Return true if successful."""
    send_msg(join_msg)
    try:
        resp_list = get_resp_list()
        if resp_list[0] == 'F':
            CmdWin.insert(1.0, "[Error]" + resp_list[1])
            return False
        else:
            if roomname is not None:
                global MSID
                MSID = resp_list[1]
                CmdWin.insert(
                    1.0, "\nYou have created a new chatroom [" +
                    roomname + "]")

            # a list to store the username, IP and port no. of members
            # in a chatroom
            usr_list = resp_list[2:-2]
            for i in range(0, len(usr_list), 3):
                CmdWin.insert(1.0, "\n" + '   '.join(usr_list[i:i + 3]))
            CmdWin.insert(1.0, "\nusername   userIP   userPort")
            return True
    except socket.error as emsg:
        recv_err(emsg)
        return False


#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")
win.protocol("WM_DELETE_WINDOW", do_Quit)

# Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5,
              fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

# Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='8', relief=RAISED,
                text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8)
Butt02 = Button(topmidframe, width='8', relief=RAISED,
                text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8)
Butt03 = Button(topmidframe, width='8', relief=RAISED,
                text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8)
Butt04 = Button(topmidframe, width='8', relief=RAISED,
                text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8)
Butt05 = Button(topmidframe, width='8', relief=RAISED,
                text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8)

# Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

# Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5,
              exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)


def main():
    """Main function."""
    global keep_alive_thd
    sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if len(sys.argv) != 4:
        print("P2PChat.py <server address> <server port no.> <my port no.>")
        sys.exit(2)
    server_address = sys.argv[1]
    server_port_no = int(sys.argv[2])
    local_port_no = int(sys.argv[3])
    # create socket and connected to the dedicated server
    try:
        sockfd.bind(('', local_port_no))
        sockfd.connect((server_address, server_port_no))
    except socket.error as emsg:
        print("Socket error: ", emsg)
        sys.exit(1)
    # print out the notification once the connection has established
    print("The connetion with ", sockfd.getpeername(), "has been established.")

    def keep_alive():
        while not quit_req:
            for i in range(40):
                sleep(0.5)
                # checking whether main thread indicates termination
                if quit_req:
                    return
            if joinedroom:
                send_join_msg()

    keep_alive_thd = Thread(target=keep_alive)
    keep_alive_thd.start()
    win.mainloop()


if __name__ == "__main__":
    main()
