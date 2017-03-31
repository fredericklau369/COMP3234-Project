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
from threading import Thread, Lock

class State():
    """An enum representing different states."""
    START = 1
    NAMED = 2
    JOINED = 3
    CONNECTED = 4
    TERMINATED = 0

    def __init__(self):
        self.lock = Lock()
        self.state = State.START

    def __setattr__(self, name, value):
        if name == 'state':
            self.lock.acquire()
            super(State, self).__setattr__(name, value)
            self.lock.release()
        else:
            super(State, self).__setattr__(name, value)

    def __eq__(self, value):
        return self.state == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def set(self, value):
        self.state = value

    def has_joined(self):
        return self.state >= 3


class UserDict(dict):
    """
    A sorted dictionary storing user data, using hash id as key.

    Values of each user is a list, consist of
    username, IP, port no., socket object, and last message id.
    """
    def __init__(self):
        super(UserDict, self).__init__()
        self.sorted_hids = []
        self.lock = Lock()

    def __setitem__(self, hid, value):
        self.lock.acquire()
        if hid not in self.sorted_hids:
            n = len(self.sorted_hids)
            i = -1
            for i in range(0, n):
                if self.sorted_hids[i] > hid:
                    break
            if i == n - 1:
                self.sorted_hids.append(hid)
            else:
                self.sorted_hids.insert(i, hid)
        result = super(UserDict, self).__setitem__(hid, value)
        self.lock.release()
        return result

    def __delitem__(self, hid):
        self.lock.acquire()
        self.sorted_hids.remove(hid)
        result = super(UserDict, self).__delitem__(hid)
        self.lock.release()
        return result

    def __iter__(self):
        self.keys()

    def pop(self, hid):
        value = self[hid]
        del self[hid]
        return value

    def keys(self):
        for hid in self.sorted_hids:
            yield hid

    def values(self):
        for hid in self.sorted_hids:
            yield self[hid]

    def items(self):
        for hid in self.sorted_hids:
            yield (hid, self[hid])

    def itemsfrom(self, index):
        hid = self.sorted_hids[index]
        yield (hid, self[hid])
        gen = (x for x in self.sorted_hids)
        while next(gen) != hid:
            pass
        for x in gen:
            yield (x, self[x])
        gen = (x for x in self.sorted_hids)
        for x in self.sorted_hids:
            if x == hid:
                break
            yield (x, self[x])

    def clear(self):
        self.lock.acquire()
        self.sorted_hids.clear()
        result = super(UserDict, self).clear()
        self.lock.release()
        return result

    def index(self, i):
        return self.sorted_hids.index(i)

#
# Global variables
#
curr_state = State() # The current state
sockfd = socket.socket()  # Socket object for connection to server
p2psock = socket.socket() # Socket for accepting incoming TCP connection request
MSID = -1  # The hash value of all membership info
roomname = '' # The roomname of the chatroom
join_msg = ''  # Message being sent to server in order to join the chatroom
users = UserDict() # Store hash ids, usernames, IPs, ports, sockets, and last message ids
my_hid = 0 # The hash id of this user
me = None # My user info


#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address),
# and str(Port) to form the input to this hash function
#
def sdbm_hash(instr):
    """A hash function."""
    hash = 0
    for c in instr:
        hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
    return hash & 0xffffffffffffffff


#
# Functions to handle user input
#

def do_User():
    """Register username."""
    global username, my_hid, me
    instr = userentry.get()
    if curr_state.has_joined():
        # User has already connected to server
        CmdWin.insert(1.0, "\n[Remind]Name cannot be changed "
                      "since you have joined a chatroom."
                      "\n[Remind]Your current username: " + me['name'])
        return
    elif len(instr) == 0:
        # Blank input
        CmdWin.insert(1.0, "\n[Remind]Username cannot be blank.")
        return
    elif len(instr) > 32:
        # Input is too long
        CmdWin.insert(
            1.0, "\n[Remind]Username is too long, please register "
                 "a name with less than 32 characters.")
        return
    elif curr_state == State.NAMED:
        # Already named
        outstr = "\n[User] New username: " + instr +\
                 "\n[User] Old username: " + me['name']
    else:
        # Not named
        outstr = "\n[User] username: " + instr
        curr_state.set(State.NAMED)
    me = users.pop(my_hid)
    me['name'] = instr
    my_hid = sdbm_hash(me['name'] + me['ip'] + str(me['port']))
    users[my_hid] = me
    CmdWin.insert(1.0, outstr)
    clear_input()


def do_List():
    """List all available chatrooms."""
    list_msg = "L::\r\n"
    send_msg(sockfd, list_msg)
    try:
        resp_list = get_resp_list(sockfd)
        if not resp_list:
            # Connection error
            sys.exit(1)
        elif resp_list[0] == "G" and resp_list[1] == '':
            # No chatrooms
            CmdWin.insert(1.0, "\nNo chatroom group")
        else:
            # Has chatrooms
            for chatroomName in resp_list[1:-2]:
                CmdWin.insert(1.0, "\n" + chatroomName)
            CmdWin.insert(1.0, "\nchatroom name")
    except socket.error as emsg:
        recv_err(emsg)


def do_Join():
    """Join a chatroom."""
    global MSID, roomname
    if curr_state.has_joined():
        # User has already connected to server
        CmdWin.insert(
            1.0, "\n[Remind]Failed. You have already joined a chatroom group.")
    elif curr_state == State.START:
        # Not named
        CmdWin.insert(
            1.0, "\nPlease input your username first, "
            "then press the [User] button")
    elif len(userentry.get()) == 0:
        # Blank input
        CmdWin.insert(
            1.0, "\n[Remind]Please input the name of the room "
            "that you want to join")
    else:
        # Valid input
        global join_msg
        roomname = userentry.get()
        join_msg = "J:%s:%s:%s:%d::\r\n" %\
            (roomname, me['name'], me['ip'], me['port'])
        send_msg(sockfd, join_msg)
        try:
            resp_list = get_resp_list(sockfd)
            if resp_list is None:
            # Connection lost
                sys.exit(1)
            elif not resp_list:
            # Error response
                return
        except socket.error as emsg:
            recv_err(emsg)
            return

        update_users(resp_list) # Refresh user list

        clear_input()
        curr_state.set(State.JOINED)
        if len(users) == 1:
            CmdWin.insert(
               1.0, "\nYou have created a new chatroom [%s]" % roomname)
            return
        setup_fwd_link() # Try to setup foward link


def do_Send():
    """Send a message across the chatroom."""
    text = userentry.get()
    if len(text) == 0:
        # Blank input
        CmdWin.insert(1.0, "\n[Remind]Field cannot be blank.")
        return
    text_msg = 'T:%s:%d:%s:%d:%d:%s::\r\n' %\
        (roomname, my_hid, me['name'], me['msgid'], len(text), text)
    process_text_msg(text_msg.split(':')) # Send to myself
    msgId += 1
    for usr in users.values():
        sock = usr['sock']
        if sock is not None:
            send_msg(sock, text_msg)


def do_Quit():
    """Quit the program."""
    curr_state.set(State.TERMINATED)
    sockfd.close()
    p2psock.close()
    for usr in users.values():
        sock = usr['sock']
        if sock is not None:
            sock.close()
    sys.exit(0)


def clear_input():
    """Clear the input box."""
    userentry.delete(0, END)


def send_msg(sock, msg):
    """Send a message."""
    sock.send(msg.encode('ascii'))


def get_resp_list(sock):
    """Wait and return a list of responses from socket."""
    rmsg = ''
    while True:
        rmsg += sock.recv(1024).decode('ascii')
        if len(rmsg) == 0:
            # Connection broken
            found = False
            for hid, usr in users.items():
                a_sock = usr['sock']
                if a_sock is not None:
                    if a_sock.getpeername() == sock.getpeername():
                        found = True
                        break
            if found:
                CmdWin.insert(1.0, "\nConnection to %s is broken" % str(sock.getpeername()))
                del users[hid] # Remove the user
            sock.close()
            return None
    # split the response message into a list of tokens
        if rmsg[-2:] == '\r\n':
            break
    rmsg = rmsg.split(':')
    if rmsg[0] == 'F':
        CmdWin.insert(1.0, "\n[Error]" + rmsg[1])
        return []
    return rmsg


def setup_fwd_link():
    """Setup a forward link to another peer if possible."""
    if curr_state != State.JOINED:
        return
    n = len(users)
    if n < 2:
        return
    i = users.index(my_hid)
    handshake_msg = "P:%s:%s:%s:%d:%d::\r\n" %\
        (roomname, me['name'], me['ip'], me['port'], me['msgid'])

    for hid, usr in users.itemsfrom((i + 1) % n):
        if hid == my_hid:
            break
        if curr_state != State.JOINED:
            break
        if usr['sock'] is not None:
            continue

        # Try to setup forward link
        try:
            fwdsocket = socket.socket() # A socket to establish forward link
            fwdsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            fwdsocket.connect((usr['ip'], usr['port']))
            send_msg(fwdsocket, handshake_msg)
            me['msgid'] += 1
            resp_list = get_resp_list(fwdsocket)

            if (not resp_list) | (resp_list[0] != 'S'):
                fwdsocket.close()
                continue

        except socket.error as emsg:
            recv_err(emsg)
            continue

        # Forward link established.
        usr['sock'] = fwdsocket
        usr['msgid'] = int(resp_list[1])
        curr_state.set(State.CONNECTED)
        CmdWin.insert(
            1.0, '\nTCP connection to user "%s" (%s:%d)'
            % (usr['name'], usr['ip'], usr['port']))
        t = Thread(target=peer_listener, args=(fwdsocket, True))
        t.daemon = True
        t.start()
        break



def update_users(arg):
    """Update the list of users by server response from join request."""
    if isinstance(arg, socket.socket):
        # arg is a socket, send join request first
        send_msg(arg, join_msg)
        return update_users(get_resp_list(arg))

    # arg is a list of response from join request
    resp_list = arg
    if resp_list[0] != 'M': # Not a response from join request
        return
    global MSID
    i = int(resp_list[1])
    if MSID == i: # List unchanged
        return

    MSID = i
    resp_list = resp_list[2:-2]
    for i in range(0, len(resp_list), 3):
        a_usr = resp_list[i:i + 3] # username, address, port no.
        hash_id = sdbm_hash(''.join(a_usr))
        a_usr[2] = int(a_usr[2]) # cast port no. to int
        if hash_id not in users:
            users[hash_id] = {
                'name': a_usr[0], 'ip': a_usr[1],
                'port': int(a_usr[2]), 'sock': None, 'msgid': 0}

    buf = ['\nusername        userIP          userPort\n']
    for usr in users.values():
        buf.append('%-16s%-16s%-16d\n' % (usr['name'], usr['ip'], usr['port']))
    CmdWin.insert(1.0, ''.join(buf))


def recv_err(err):
    """Handle an error received."""
    raise err
    print ("\nReceive error: ", err)


def peer_listener(sock, is_fwd_link=False):
    """Handle messages from peer."""
    while curr_state != State.TERMINATED:
        resp_list = get_resp_list(sock)
        if not resp_list:
            # Connection Broken
            if is_fwd_link:
                # Try to establish forward link again.
                update_users(sockfd)
                curr_state.set(State.JOINED)
                setup_fwd_link()
            return
        elif resp_list[0] == 'P':
            # Incoming handshaking requests
            usr = resp_list[2:5]
            CmdWin.insert(
                1.0, '\nReceive TCP connection from user "%s" (%s:%s)'
                % tuple(usr))
            send_msg(sock, 'S:%d::\r\n' % me['msgid'])
            me['msgid'] += 1
            hash_code = sdbm_hash(''.join(usr))
            if hash_code not in users:
                update_users(sockfd)
            usr =  users[hash_code]
            usr['sock'] = sock
            usr['msgid'] = int(resp_list[5])
        elif resp_list[0] == 'T':
            process_text_msg(resp_list)


def process_text_msg(resp_list):
    """Parse and display text messages."""
    originHID = int(resp_list[2])
    resp_msgId = int(resp_list[4])
    if originHID not in users:
        update_users(sockfd)
    if users[originHID]['msgid'] == resp_msgId: # Duplicated message
        return
    users[originHID]['msgid'] = resp_msgId
    for hid, usr in users.items():
        if hid != originHID: # Send to all available connections
            sock = usr['sock']
            if sock is not None:
                send_msg(sock, ':'.join(resp_list))
    # Display the message
    text = ':'.join(resp_list[6:-2])
    MsgWin.insert(1.0, '\n%s: %s' % (resp_list[3], text))



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
    if len(sys.argv) != 4:
        print("P2PChat.py <server address> <server port no.> <my port no.>")
        sys.exit(2)
    server_address = sys.argv[1]
    server_port_no = int(sys.argv[2])
    local_port_no = int(sys.argv[3])
    # Create socket and connected to the dedicated server
    sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    p2psock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sockfd.connect((server_address, server_port_no))
        local_address = sockfd.getsockname()[0]
        p2psock.bind((local_address, local_port_no))
        p2psock.listen(5)
    except socket.error as emsg:
        print("Socket error: ", emsg)
        sys.exit(1)
    # Print out the notification once the connection has established
    print("The connetion with %s has been established." % str(sockfd.getpeername()))

    global me
    me = {'name': None, 'ip': local_address,
          'port': local_port_no, 'sock': None, 'msgid': 0}
    users[my_hid] = me


    def accept_tcp():
        # Accept TCP connections from peers
        while curr_state != State.TERMINATED:
            conn, addr = p2psock.accept()
            t = Thread(target=peer_listener, args=(conn,))
            t.daemon = True
            t.start()
            
    
    def keep_alive():
        while curr_state != State.TERMINATED:
            for i in range(20):
                sleep(1)
                # checking whether main thread indicates termination
                if curr_state == State.TERMINATED:
                    return
                elif curr_state == State.JOINED:
                    setup_fwd_link()
            if curr_state.has_joined():
                update_users(sockfd)

    keep_alive_thd = Thread(target=keep_alive)
    keep_alive_thd.daemon = True
    keep_alive_thd.start()
    p2p_thd = Thread(target=accept_tcp)
    p2p_thd.daemon = True
    p2p_thd.start()
    win.mainloop()


if __name__ == "__main__":
    main()
