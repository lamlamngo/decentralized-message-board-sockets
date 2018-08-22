import threading
import queue
import time
import random
import logging
import traceback, sys
from socket import *
from blockchain_constants import *

class Server:


    
    def __init__(self, blockchain, do_peering, accept_blocks, accept_non_local_msgs):

        # Set up logging.
        # create logger with 'spam_application'
        self.log = logging.getLogger('Server')
        self.log.setLevel(logging.DEBUG)
        # create file handler which logs even debug messages
        fh = logging.FileHandler('server.log')
        fh.setLevel(logging.DEBUG)
        # create console handler with a higher log level
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        # create formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # add the handlers to the logger
        self.log.addHandler(fh)
        self.log.addHandler(ch)

        self.log.warning("=========== Server logging started ==========")

        # Determine host name.
        s = socket(AF_INET, SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self.host = s.getsockname()[0]
        s.close()
        
        self.lock = threading.Lock()

        self.peering_file = "peers.txt"
        self.read_peers()

        # Flags to restrict functionality.
        self.do_peering = do_peering
        self.accept_blocks = accept_blocks
        self.accept_non_local_msgs = accept_non_local_msgs
        
        self.broadcast_queue = queue.Queue()
        self.blockchain = blockchain
        self.log.warning("============ Server init complete ===========")



    def add_peer(self, host):

        if host == MAIN_HOST and host == self.host:
            return True

        with self.lock:
            if len(self.peers) < MAX_PEERS and not self.is_peer(host):
                self.peers.append((gethostbyname(host), 0))
                #self.write_peers()
                return True
            return False

    def punish_peer(self, host):

        if host == MAIN_HOST:
            return

        self.log.info("Thread: %d - Warning: Punishing peer %s." %
                      (threading.get_ident() % 10000, host))
        
        punished = False
        
        new_peers = []
        #print(self.peers)
        with self.lock:
            for i in range(len(self.peers)):
                if (self.peers[i][0] == host):
                    fails = self.peers[i][1] + 1
                    punished = True
                    if (fails <= MAX_PEER_FAILURE):
                        new_peers.append((host, fails))
                else:
                    new_peers.append(self.peers[i])

            self.peers = new_peers
            
        if punished:
            self.write_peers()
                       
    
    def read_peers(self):

        with self.lock:
            self.log.info("Reading peers from %s." % self.peering_file)
            self.peers = [(MAIN_HOST, 0)]
            with open(self.peering_file, 'r') as f:
                
                for line in f.readlines():
                    line = line.strip()
                    if len(line) <= 0:
                        break
                    host = line
                    self.peers.append((gethostbyname(host), 0))

        self.confirm_peers()
                    
    def write_peers(self):

        with self.lock:
            with open(self.peering_file, 'w') as f:
                for peer in self.peers:
                    f.write(peer[0] + "\n")
            self.log.info("Wrote peers to %s: %s" % (self.peering_file, str(self.peers)))

    def is_peer(self, host):

        if host == '' or host == "localhost" or host == '127.0.0.1' or host == self.host:
            return True

        for peer in self.peers:
            if gethostbyname(host) == gethostbyname(peer[0]): 
                return True

        return False
                
    def run(self):

                    
        addr = ('', DEFAULT_PORT)
        buf_len = 4096

        try:
            sock = socket(AF_INET,SOCK_STREAM)
            sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            sock.bind(addr)
            sock.listen(1)
            self.log.info("Started up on port %d" % addr[1])
        except:
            self.log.error("Unable to start on port %d" % addr[1])
            exit()

        # Reset peers
        t = threading.Thread(target=self.request_peers)
        t.start()
            
        # Start broadcast thread
        t = threading.Thread(target=self.broadcast)
        t.start()

        # Start update thread
        t = threading.Thread(target=self.get_updates)
        t.start()
        
        # Main server loop
        cleanup = 0
        while True:
            conn, cl_addr = sock.accept()

            #print("received connection")
            
            # Handle connection on new thread
            t = threading.Thread(target=self.handle_connection, args=(conn, cl_addr))
            t.start()

            # Maintaince
            if cleanup > 10000:
                # Locate new peers
                self.log.info("Cleaning up.")
                if len(self.peers) < MIN_PEERS:
                    t = threading.Thread(target=self.request_peers)
                    t.start()
                cleanup = 0
            else:
                cleanup += 1

            


    def confirm_peers(self):

        good_peers = []
        for peer in self.peers:
            if self.confirm_peer(peer[0]):
                good_peers.append(peer[0])
        
        with self.lock:
            self.peers = []
            
        for peer in good_peers:
            self.add_peer(peer)
        
        self.write_peers()
                
    def confirm_peer(self, host):

        good = True
        sock = socket(AF_INET, SOCK_STREAM)
        try:
            sock = create_connection((host, DEFAULT_PORT),TIMEOUT)
            f_in = sock.makefile('r')                
            f_out = sock.makefile('w')                
            f_out.write("PEER_REQUEST\n")
            f_out.flush()
            time.sleep(WAIT_TIME)
            ack = f_in.readline().strip()
            if ack != "ACK":
                good = False
                self.log.warning("Thread: %d - Peer request denied. %s" %
                                 (threading.get_ident() % 10000, host))
            else:
                self.log.info("Thread: %d - Peer request accepted. %s" %
                              (threading.get_ident() % 10000, host))
            sock.close()
        except:
            good = False
            self.log.info("Thread: %d - Peer request failed. %s" %
                          (threading.get_ident() % 10000, host))
            try:
                sock.close()
            except:
                pass

        return good
        
        

    def request_peers(self):

        self.log.info("Thread: %d - Start requesting peers. %d peers currently" %
                      (threading.get_ident() % 10000, len(self.peers) + 1))
        
        bad_peers = []
        new_peers = []
        for peer in self.peers:
            sock = socket(AF_INET, SOCK_STREAM)
            try:
                sock = create_connection((peer[0], DEFAULT_PORT),TIMEOUT)
                f_in = sock.makefile('r')                
                f_out = sock.makefile('w')                
                f_out.write("PEERS_REQUEST\n")
                f_out.flush()
                time.sleep(WAIT_TIME)
                num = int(f_in.readline().strip())
                for i in range(num):
                    tokens = f_in.readline().strip().split(":")
                    host = tokens[0]
                    port = int(tokens[1])
                    new_peers.append(host)
                sock.close()

            except:
                bad_peers.append(peer)
                try:
                    sock.close()
                except:
                    pass
                    
        for peer in bad_peers:
            self.punish_peer(peer[0])

        random.shuffle(new_peers)
        for new_peer in new_peers:
            if not self.is_peer(new_peer) and len(self.peers) <= MAX_PEERS:
                if self.confirm_peer(new_peer):
                    self.add_peer(new_peer)

        self.write_peers()
        
        self.log.warning("Thread: %d - Complete requesting peers. %d peers currently" %
                         (threading.get_ident() % 10000, len(self.peers) + 1))
                
    def get_updates(self):

        self.log.warning("Thread: %d - Started updating from peers" %
                         (threading.get_ident() % 10000))

        bad_peers = []
        for peer in self.peers:
            sock = socket(AF_INET, SOCK_STREAM)
            try:
                sock = create_connection((peer[0], DEFAULT_PORT), TIMEOUT)
                f_in = sock.makefile('r')                
                f_out = sock.makefile('w')                
                f_out.write("UPDATE_REQUEST\n")
                f_out.flush()
                f_out.write("%f\n" % 0) #(self.blockchain.latest_time - UPDATE_PAD))
                f_out.flush()
                time.sleep(WAIT_TIME)  
                count = int(f_in.readline().strip())
                for i in range(count):
                    self.blockchain.add_block_str(f_in.readline().strip())
                sock.close()
                self.log.info("Thread: %d - Received %d blocks from %s." %
                                 (threading.get_ident() % 10000, count, peer[0]))
            except:
                bad_peers.append(peer[0])
                try:
                    sock.close()
                except:
                    pass
                    
        for peer in bad_peers:
            self.punish_peer(peer)

        self.log.warning("Thread: %d - Completed updating from peers" %
                         (threading.get_ident() % 10000))

                    

    def broadcast(self):

        while True:
            bad_peers = []
            
            # Broadcast our own mined blocks first
            item = self.blockchain.get_new_block_str()
            item_type = BLOCK_TYPE
            if (item == None):
                # Broadcast peers messages otherwise
                try:
                    (item_type, item) = self.broadcast_queue.get_nowait()
                except:
                    # Wait if nothing to broadcast
                    time.sleep(WAIT_TIME)
                    continue

            self.log.info("Broadcasting %s to peers." % ("message" if item_type == MESSAGE_TYPE else "block"))
                
            for peer in self.peers:
                sock = socket(AF_INET, SOCK_STREAM)
                try:
                    sock = create_connection((peer[0], DEFAULT_PORT),TIMEOUT)
                    f_out = sock.makefile('w')                
                    if item_type == MESSAGE_TYPE:
                        f_out.write("MESSAGE_BROADCAST\n")
                    else:
                        f_out.write("BLOCK_BROADCAST\n")
                    f_out.flush()
                    f_out.write(item + "\n") 
                    f_out.flush()
                    time.sleep(WAIT_TIME)
                    sock.close()
                except:
                    self.log.warning("Peer failed to receive broadcasting")
                    
                    bad_peers.append(peer)
                    try:
                        sock.close()
                    except:
                        pass
                        
            for peer in bad_peers:
                self.punish_peer(peer[0])

            self.log.info("Broadcasting complete.")        

    
    def handle_connection(self, conn, cl_addr):

        try:
            f_in = conn.makefile('r')
            f_out = conn.makefile('w')

            command = f_in.readline().strip()
            #print("command:", command)
            
            cl_host = cl_addr[0]
            cl_port = int(cl_addr[1])


            #self.log.info("Thread: %d - Command: %s - From: %s:%d" %
            #              (threading.get_ident() % 10000, command, cl_host, cl_port))

            if not self.is_peer(cl_host) and command != "PEER_REQUEST":
                self.log.warning("Thread: %d - Command: %s - From: %s:%d - Warning: Denied, peer not recognized" %
                                 (threading.get_ident() % 10000, command, cl_host, cl_port))
                f_out.write("ERROR Denied, peer not recognized\n")
                f_out.flush()

            elif command == "PEER_REQUEST":
                if self.is_peer(cl_host):
                    self.log.warning("Thread: %d - Command: %s - From: %s:%d - Already accepted peer." %
                                     (threading.get_ident() % 10000, command, cl_host, cl_port))
                    f_out.write("ACK\n")
                    f_out.flush()
                elif not self.add_peer(cl_host):
                    self.log.warning("Thread: %d - Command: %s - From: %s:%d - Warning: Denied, too many active peers." %
                                     (threading.get_ident() % 10000, command, cl_host, cl_port))
                    f_out.write("ERROR Denied, too many active peers\n")
                    f_out.flush()
                else:
                    self.write_peers()
                    self.log.info("Thread: %d - Command: %s - From: %s:%d - Accepted peer." %
                                  (threading.get_ident() % 10000, command, cl_host, cl_port))
                    f_out.write("ACK\n")
                    f_out.flush()


            elif command == "MESSAGE_BROADCAST":
                ## Add to queue and send to other peers
                msg_str = f_in.readline().strip()
                if not self.accept_non_local_msgs and (cl_host == '' or cl_host == 'localhost' or cl_host == '127.0.0.1'):
                    self.log.info("Thread: %d - Command: %s - From: %s:%d - Message ignored" %
                                  (threading.get_ident() % 10000, command, cl_host, cl_port))
                    self.broadcast_queue.put((MESSAGE_TYPE, msg_str))
                    f_out.write("ACK\n")
                    f_out.flush()
                    
                elif self.blockchain.get_message_queue_size() >= MSG_BUFFER_SIZE:
                    self.log.warning("Thread: %d - Command: %s - From: %s:%d - Received duplicate or invalid message, ignoring" %
                                     (threading.get_ident() % 10000, command, cl_host, cl_port))
                    f_out.write("FAILURE - Message buffer full, try again later.\n")
                    f_out.flush()
                    
                elif self.blockchain.add_message_str(msg_str):
                    # Only broadcast if valid and not seen
                    self.log.info("Thread: %d - Command: %s - From: %s:%d - Received new message to process and broadcast" %
                                  (threading.get_ident() % 10000, command, cl_host, cl_port))
                    self.broadcast_queue.put((MESSAGE_TYPE, msg_str))
                    f_out.write("ACK\n")
                    f_out.flush()

                else:
                    self.log.info("Thread: %d - Command: %s - From: %s:%d - Received duplicate or invalid message, ignoring" %
                                  (threading.get_ident() % 10000, command, cl_host, cl_port))
                    f_out.write("FAILURE - Invalid or duplicate\n")
                    f_out.flush()


            elif command == "BLOCK_BROADCAST":
                block_str = f_in.readline().strip()
                if not self.accept_blocks:
                    self.log.info("Thread: %d - Command: %s - From: %s:%d - Ignored block broadcast" %
                                  (threading.get_ident() % 10000, command, cl_host, cl_port))
                    self.broadcast_queue.put((BLOCK_TYPE, block_str))
                    f_out.write("ACK\n")
                    f_out.flush()
                elif self.blockchain.add_block_str(block_str):  
                    # Only broadcast if valid and not seen
                    self.log.info("Thread: %d - Command: %s - From: %s:%d - Received new block to process and broadcast" %
                                  (threading.get_ident() % 10000, command, cl_host, cl_port))
                    self.broadcast_queue.put((BLOCK_TYPE, block_str))
                    f_out.write("ACK\n")
                    f_out.flush()
                else:
                    self.log.info("Thread: %d - Command: %s - From: %s:%d - Received duplicate or invalid message, ignoring" %
                                  (threading.get_ident() % 10000, command, cl_host, cl_port))
                    f_out.write("FAILURE - Invalid or duplicate.\n")
                    f_out.flush()

            elif command == "UPDATE_REQUEST":
                try:
                    t = float(f_in.readline().strip())
                    block_strs = self.blockchain.get_all_block_strs(t)
                    f_out.write("%d\n" % len(block_strs))
                    f_out.flush()
                    for block_str in block_strs:
                        f_out.write(block_str + "\n")
                        f_out.flush()
                    self.log.info("Thread: %d - Command: %s - From: %s:%d - Sent %d blocks to update peer" %
                                     (threading.get_ident() % 10000, command, cl_host, cl_port, len(block_strs)))
                except:
                    self.log.warning("Thread: %d - Command: %s - From: %s:%d - Warning: Recieved invalid UPDATE_REQUEST" %
                                  (threading.get_ident() % 10000, command, cl_host, cl_port))
                    f_out.write("ERROR Time not recognized")
                    f_out.flush()

            elif command == "PEERS_REQUEST":
                if not self.do_peering:
                    self.log.info("Thread: %d - Command: %s - From: %s:%d - Ignored peers request." %
                                (threading.get_ident() % 10000, command, cl_host, cl_port))
                    f_out.write(str(0) + "\n")
                    f_out.flush()
                else:
                
                    with self.lock:
                        f_out.write(str(len(self.peers)) + "\n")
                        f_out.flush()
                        for peer in self.peers:
                            f_out.write(peer[0] + ":" + str(peer[1]) + "\n")
                            f_out.flush()
                        self.log.info("Thread: %d - Command: %s - From: %s:%d - Sent %d peers to peer" %
                                      (threading.get_ident() % 10000, command, cl_host, cl_port, len(self.peers)))
            else:
                self.log.warning("Thread: %d - Command: %s - From: %s:%d - Warning Invalid request from peer" %
                                 (threading.get_ident() % 10000, command, cl_host, cl_port))
                f_out.write("ERROR Command not recognized\n")
                f_out.flush()

        except:
            self.log.error("Thread: %d - Command: %s - From: %s:%d - Exception in handling request\n%s" %
                           (threading.get_ident() % 10000, command, cl_host, cl_port, traceback.format_exc()))

        conn.close()
                                        





