#!/usr/bin/python3

# Student name and No.:
# Student name and No.:
# Development platform:
# Python version:
# Version:


from tkinter import *
import sys
import socket
import time
import threading

#
# Global variables
#
joinedroom = False  #Boolean variable to determine whether the user has joined a chatroom
username = ""   #Store the registered username for joining the chatroom
sockfd = socket.socket()  #create a socket object for connection 
MSID = 0
joinRequest = "" #message being sent to server in order to join the chatroom
terminate = False #Inform the keepalive thread to termiante when the user press quit button
keepalive_thd = None



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
	global username
	if joinedroom != True:
		outstr = "\n[User] username: "+userentry.get()
		if len(userentry.get()) > 32: 
			CmdWin.insert(1.0, "\n[Remind]Username is too long, please register a name with less than 32 characters.")
		elif len(userentry.get()) == 0:
			CmdWin.insert(1.0, "\n[Remind]Username cannot be blank.")
		else:
			if username  != "":
				outstr = "\n[User] Old username: "+username
				CmdWin.insert(1.0, outstr)
				outstr = "\n[User] New username: "+userentry.get()
			username = userentry.get()
			CmdWin.insert(1.0, outstr)
	else:
		CmdWin.insert(1.0, "\n[Remind]Name cannot be changed since you have joined a chatroom.")
		CmdWin.insert(1.0, "\n[Remind]Your current username: "+username)
	userentry.delete(0, END)
	
def do_List():
	global sockfd
	listRequest = "L::\r\n"
	sockfd.send(listRequest.encode('ascii'))
	try:
		rmsg = sockfd.recv(800)
		rmsg = rmsg.decode('ascii')
		if len(rmsg) == 0:
			print("connection is broken")
			sys.exit(1)
		responseTokens = rmsg.split(":")     #split the response message into a list of tokens
		if responseTokens[0] == "G" and responseTokens[1] == '':
			CmdWin.insert(1.0, "\nNo chatroom group")
		elif responseTokens[0] == "F":
			CmdWin.insert(1.0, "\n[Error] ",responseTokens[1])
		else:
			del responseTokens[0]
			responseTokens.pop()
			responseTokens.pop()
			for chatroomName in responseTokens:
				CmdWin.insert(1.0, "\n"+chatroomName)
			CmdWin.insert(1.0, "\nchatroom name")
	except socket.error as err:
		errmsg = "\nRecverror: "+err
		print(errmsg)


def do_Join():
	global joinedroom
	global sockfd
	global username
	global joinRequest
	if joinedroom == True:
		CmdWin.insert(1.0, "\n[Remind]Failed. You have already joined a chatroom group.")
	elif username == '':
		CmdWin.insert(1.0, "\nPlease input your username and press the [User] button first")
	elif len(userentry.get()) == 0:
		CmdWin.insert(1.0, "\n[Remind]Please input the name of the room that you want to join")
	else:
		roomname = userentry.get()
		userIP, userPort = sockfd.getsockname()
		joinRequest = "J:"+roomname+":"+username+":"+userIP+":"+str(userPort)+"::\r\n"
		sockfd.send(joinRequest.encode('ascii'))
		try:
			rmsg = sockfd.recv(500)
			rmsg = rmsg.decode('ascii')
			if len(rmsg) == 0:
				print("connection is broken")
				sys.exit(1)
			responseTokens = rmsg.split(':')
			if responseTokens[0] == 'F':
				CmdWin.insert(1.0, "[Error]"+responseTokens[1])
			else:
				responseTokens.pop()
				responseTokens.pop()
				global MSID
				MSID = responseTokens[1]
				memberInfo = ""   #a string to store the username,IP and port no. of a member in specific chatroom
				x = 0
				if len(responseTokens) == 5:
					CmdWin.insert(1.0, "\nYou have created a new chatroom ["+roomname+"]")
				for info in responseTokens[2:]:
					if x%3 == 0:
						memberInfo = "\n"
					memberInfo = memberInfo+info+" "
					if x%3 == 2:
						CmdWin.insert(1.0, memberInfo)
					x += 1
				CmdWin.insert(1.0, "\nusername   userIP   userPort")
				joinedroom = True
		except socket.error as err:
			errmsg = "\nRecverror: "+err
			print (errmsg)
	userentry.delete(0, END)

def keepAlive_thd():
	global joinRequest
	global joinedroom
	global sockfd
	while (not terminate):
		for i in range(40):
			time.sleep(0.5)
			# checking whether main thread indicates termination
			if terminate:
				return
		if joinedroom:
			sockfd.send(joinRequest.encode("ascii"))
			try:
				rmsg = sockfd.recv(500)
				rmsg = rmsg.decode('ascii')
				if len(rmsg) == 0:
					print("connection is broken")
					sys.exit(1)
				responseTokens = rmsg.split(':')
				if responseTokens[0] == 'F':
					CmdWin.insert(1.0, "\n[Error]"+responseTokens[1])
				else:
					responseTokens.pop()
					responseTokens.pop()
					MSID = responseTokens[1]
					memberInfo = ""   #a string to store the username,IP and port no. of a member in specific chatroom
					x = 0
					for info in responseTokens[2:]:
						if x%3 == 0:
							memberInfo = "\n"
						memberInfo = memberInfo+" "+info
						if x%3 == 2:
							CmdWin.insert(1.0, memberInfo)
						x += 1
					CmdWin.insert(1.0, "\nusername   userIP   userPort")
			except socket.error as err:
				errmsg = "\nRecverror: "+err
				print (errmsg)
	return


def do_Send():
	CmdWin.insert(1.0, "\nPress Send")


def do_Quit():
	terminate = True
	keepalive_thd.join()
	sockfd.close()
	sys.exit(0)

#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='8', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='8', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='8', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='8', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='8', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

def main():
	global sockfd
	global keepalive_thd
	sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		print(sys.argv[2])
		sys.exit(2)
	server_address = sys.argv[1]
	server_port_no = int(sys.argv[2])
	local_port_no = int(sys.argv[3])
	#create socket and connected to the dedicated server
	try:
		sockfd.bind(('',local_port_no))
		sockfd.connect((server_address, server_port_no))
	except socket.error as emsg:
		print("Socket error: ", emsg)
		sys.exit(1)
	# print out the notification once the connection has established
	print("The connetion with ", sockfd.getpeername(), "has been established.")
	keepalive_thd = threading.Thread(name="keepalive", target=keepAlive_thd)
	keepalive_thd.start()
	win.mainloop()

if __name__ == "__main__":
	main()

