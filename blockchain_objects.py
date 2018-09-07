#Author: Lam Ngo, Elizabeth Ricci and Jonathan Kimber
import hashlib
import hmac
from binascii import *
from blockchain_constants import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import threading
import copy
import functools
import time
class Ledger:

    """ An object to store the blockchain
    """

    def __init__(self, private_key, pubhex):

        self.messages_last_added = 0

        self.private_key = private_key
        self.pubhex = pubhex

        self.genesis_block = None

        self.current_lowest = []
        self.current_lowest_level = 0

        self.total_blocks = 0

        self.latest_safe_level = 0

        self.all_blocks_by_hash = {}
        self.all_messages_by_signature = {}

        self.parent_lock = threading.Lock()
        self.file_lock = threading.Lock()
        self.block_dict_lock = threading.Lock()
        self.msg_dict_lock = threading.Lock()

        self.last_block_added = None
        self.root_node_last = []
        self.load_from_file()

        self.readable_messages = 0

    # loads ledger from file
    def load_from_file(self):
        # if file exists, get everything from it
        # if stuff isn't right format don't get it
        with open('ledger.txt', 'r') as f:
            for line in f.readlines():
                if line is not None:
                    block_list = line.split("|")
                    block = Block(block_list[0],block_list[1],block_list[3],block_list[2],block_list[4:-1])
                    block.set_hash(block_list[-1].strip())
                    if self.get_genesis_block() is None:
                        self.add_block(block, None)
                    else:
                        self.add_block(block, self.find_from_hash(block_list[1]))

    # adds block to ledger in memory
    # we assume block_to_add is a valid block, and parent_block is valid
    def add_block(self, block_to_add, parent_block):
        self.last_block_added = block_to_add

        # no genesis block, and parent block is None (intentionally the genesis block)
        with self.block_dict_lock:
            with self.msg_dict_lock:
                with self.parent_lock:
                    if self.genesis_block is None and parent_block is None:
                        self.current_lowest_level = 1
                        block_to_add.set_level(self.current_lowest_level)
                        block_to_add.set_root_node(block_to_add)
                        self.genesis_block = block_to_add

                        self.current_lowest = [self.genesis_block]

                        self.all_blocks_by_hash[block_to_add.get_hash()] = block_to_add

                        for ea_message in block_to_add.get_messages_objects():
                            self.all_messages_by_signature[ea_message.get_signature()] = ea_message

                        self.total_blocks = 1

                        #write the messages of the genesis block
                        try:
                            f = open("messages.txt","w")
                            for mess in self.genesis_block.get_messages_objects():
                                a_mess = mess.get_msg_body()
                                if len(a_mess) == 4:
                                    f.write("Public message: " + a_mess[0] + ": " + unhexlify(a_mess[1]).decode('utf-8'))
                                    f.write("\n")
                                else:
                                    if self.pubhex == a_mess[2]:
                                        decoded_message = self.private_key.decrypt(
                                            unhexlify(a_mess[1]),
                                            padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                            algorithm=hashes.SHA1(),
                                            label=None
                                            )
                                        )
                                        f.write("Private message: " + a_mess[0] + ": " + decoded_message)
                                        f.write("\n")

                            f.close()
                        except Exception as e:
                            print(e)

                    else:
                        if parent_block is not None:
                            try:
                                parent_block.add_child(block_to_add)
                                block_to_add.set_parent(parent_block)
                                block_to_add.set_level(parent_block.get_level()+1)

                                # we're sending in a parent block, and the parent block is the genesis block
                                if parent_block is not None and parent_block.is_equal(self.get_genesis_block()):
                                    block_to_add.set_root_node(block_to_add)
                                elif parent_block is not None:
                                    block_to_add.set_root_node(parent_block.get_root_node())

                                i = 0
                                max_index = len(self.current_lowest)
                                while i < max_index:
                                    if self.current_lowest[i].get_block_str() == block_to_add.get_parent().get_block_str():
                                        pass
                                    if self.current_lowest[i].get_level() < block_to_add.get_level():
                                        del self.current_lowest[i]
                                        i -= 1
                                        max_index -= 1
                                    i += 1

                                if len(self.current_lowest) == 0 or self.current_lowest[0].get_level() == block_to_add.get_level():
                                    self.current_lowest += [block_to_add]

                                self.all_blocks_by_hash[block_to_add.get_hash()] = block_to_add

                                self.current_lowest_level = max(self.current_lowest_level, block_to_add.get_level())
                                self.total_blocks += 1

                                lowest = self.find_longest_chain_block()
                                if lowest is not None:
                                    #adding to the end of the longest chain
                                    if block_to_add.get_level() > lowest.get_level():
                                        if block_to_add.parent_block.is_equal(lowest):
                                            try:
                                                f = open("messages.txt", "a")
                                                for mess in block_to_add.get_messages_objects():
                                                    if not self.message_exists(mess):
                                                        a_mess = mess.get_msg_body()
                                                        if len(a_mess) == 2:
                                                            f.write("Public message: " + a_mess[0] + ": " + unhexlify(a_mess[1]).decode('utf-8'))
                                                            f.write("\n")
                                                        else:
                                                            if self.pubhex == a_mess[2]:
                                                                decoded_message = self.private_key.decrypt(
                                                                    unhexlify(a_mess[1]),
                                                                    padding.OAEP(
                                                                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                                    algorithm=hashes.SHA1(),
                                                                    label=None
                                                                    )
                                                                )
                                                                f.write("Private message: " + a_mess[0] + ": " + decoded_message)
                                                                f.write("\n")
                                                f.close()
                                            except Exception as e:
                                                print(e)
                                        #BLOCKCHAIN HAS BEEN FORKED
                                        elif not block_to_add.root_node.is_equal(lowest.root_node):
                                            print ("OVERTAKING MAIN CHAIN OVERTAKING MAIN CHAIN OVERTAKING MAINCHAIN OVERTAKING MAINCHAIN")
                                            try:
                                                f = open("messages.txt","w")
                                                for mess in self.genesis_block.get_messages_objects():
                                                    a_mess = mess.get_msg_body()
                                                    if len(a_mess) == 2:
                                                        f.write("Public message: " + a_mess[0] + ": " + unhexlify(a_mess[1]).decode('utf-8'))
                                                        f.write("\n")
                                                    else:
                                                        if self.pubhex == a_mess[2]:
                                                            decoded_message = self.private_key.decrypt(
                                                                unhexlify(a_mess[1]),
                                                                padding.OAEP(
                                                                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                                algorithm=hashes.SHA1(),
                                                                label=None
                                                                )
                                                            )
                                                            f.write("Private message: " + a_mess[0] + ": " + decoded_message)
                                                            f.write("\n")
                                                f.close()
                                            except Exception as e:
                                                print(e)
                                            try:
                                                current_block = block_to_add
                                                stack = []
                                                while not current_block.get_parent().is_equal(self.genesis_block):
                                                    for mess in current_block.get_messages_objects():
                                                        a_mess = mess.get_msg_body()
                                                        if len(a_mess) == 2:
                                                            stack.append("Public message: " + a_mess[0] + ": " + unhexlify(a_mess[1]).decode('utf-8'))
                                                        else:
                                                            if self.pubhex == a_mess[2]:
                                                                decoded_message = self.private_key.decrypt(
                                                                    unhexlify(a_mess[1]),
                                                                    padding.OAEP(
                                                                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                                    algorithm=hashes.SHA1(),
                                                                    label=None
                                                                    )
                                                                )
                                                                stack.append("Private message: " + a_mess[0] + ": " + decoded_message)
                                                    current_block = current_block.get_parent()
                                            except Exception as e:
                                                print (e)
                                            try:
                                                f = open("messages.txt","a")
                                                while len(stack) > 0:
                                                    f.write(stack.pop(0))
                                                    f.write("\n")
                                                f.close()
                                            except Exception as e:
                                                print (e)
                                elif block_to_add.parent_block.is_equal(self.genesis_block) and len(self.root_node_last) == 0:
                                    try:
                                        f = open("messages.txt", "a")
                                        for mess in block_to_add.get_messages_objects():
                                            if not self.message_exists(mess):
                                                a_mess = mess.get_msg_body()
                                                if len(a_mess) == 2:
                                                    f.write("Public message: " + a_mess[0] + ": " + unhexlify(a_mess[1]).decode('utf-8'))
                                                    f.write("\n")
                                                else:
                                                    if self.pubhex == a_mess[2]:
                                                        decoded_message = self.private_key.decrypt(
                                                            unhexlify(a_mess[1]),
                                                            padding.OAEP(
                                                            mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                            algorithm=hashes.SHA1(),
                                                            label=None
                                                            )
                                                        )
                                                        stack.append("Private message: " + a_mess[0] + ": " + decoded_message)
                                        f.close()
                                    except Exception as e:
                                        print (e)

                                #KEEP TRACK OF ALL DIFFERENT FORKS FROM THE GENESIS BLOCK
                                if parent_block.is_equal(self.genesis_block):
                                    self.root_node_last += [block_to_add]
                                else:
                                    for i in range(len(self.root_node_last)):
                                        if block_to_add.root_node.is_equal(self.root_node_last[i].root_node) and block_to_add.get_level() > self.root_node_last[i].get_level():
                                            self.root_node_last[i] = block_to_add

                                for ea_message in block_to_add.get_messages_objects():
                                    if not self.message_exists(ea_message):
                                        self.all_messages_by_signature[ea_message.get_signature()] = ea_message

                                if time.time() - self.messages_last_added > 120:
                                    self.readable_messages = len(open("messages.txt", "r").readlines())
                                    self.messages_last_added = time.time()

                                f = open("stats.txt", "w")
                                f.write("Readable messages: " + str(self.readable_messages) + "\n")
                                f.write("Total Block is " + str(self.total_blocks) + "\n")
                                f.write("Longest chain is " + str(self.find_longest_chain()) + "\n")
                                f.write("Longest fork is " + str(self.find_second_longest_chain()) + "\n")
                                f.write("Stale blocks are " + str(self.total_blocks - self.find_longest_chain()) + "\n")
                                f.write("All possible forks from the genesis block: " + "\n")
                                for i in range(len(self.root_node_last)):
                                    f.write("Chain %d: " % i  + str(self.root_node_last[i].get_level()) + "\n")
                                f.close()
                            except Exception as e:
                                print("Cannot add block. Error follows.")
                                print(e)

    # adds block to ledger.txt
    def add_to_ledger(self, block_to_add):
        with self.file_lock:
            with open("ledger.txt", "a") as ledger:
                block_ledger_string = block_to_add.get_block_str() + "|" + block_to_add.get_hash()
                ledger.write(block_ledger_string + "\n")

    # return genesis block
    def get_genesis_block(self):
        return self.genesis_block

    """ Get the last block(s) from the longest chain(s)
    """
    def get_last_blocks(self):
        if len(self.current_lowest) == 0:
            return None
        else:
            return self.current_lowest

     # returns true if block is in blockchian
    def block_exists(self, block_to_check):
        return block_to_check.get_hash() in self.all_blocks_by_hash

    # returns 1 if level of first is less than, 0 if equal to
    # and -1 if greater than 2nd block
    def chain_comparator(self, last_block_1, last_block_2):
        if last_block_1.get_level() < last_block_2.get_level():
            return 1
        elif last_block_1.get_level() == last_block_2.get_level():
            return 0
        else:
            return -1

    # returns the final block of the longest chain
    def find_longest_chain_block(self):
        try:
            if len(self.root_node_last) == 0:
                return None
            if len(self.root_node_last) == 1:
                return self.root_node_last[0]

            sorted_list = sorted(self.root_node_last, key=functools.cmp_to_key(self.chain_comparator))
            return sorted_list[0]

        except Exception as e:
            print (e)
            return -1

    def find_longest_chain(self):
        try:
            if len(self.root_node_last) == 0:
                return 0
            if len(self.root_node_last) == 1:
                return self.root_node_last[0].get_level()

            sorted_list = sorted(self.root_node_last, key=functools.cmp_to_key(self.chain_comparator))
            return sorted_list[0].get_level()

        except Exception as e:
            print (e)
            return -1
    # returns the length of the second longest chain
    def find_second_longest_chain(self):
        try:
            if len(self.root_node_last) == 0 or len(self.root_node_last) == 1:
                return 0

            sorted_list = sorted(self.root_node_last, key=functools.cmp_to_key(self.chain_comparator))
            return sorted_list[1].get_level()

        except Exception as e:
            print (e)
            return -1

    # returns a sorted list of all blocks created after time t
    def get_blocks_after(self, t):
        with self.block_dict_lock:
            valid_blocks = dict((block_hash, block) for block_hash, block in self.all_blocks_by_hash.items() if float(block.get_time()) > t)
            sorted_list = sorted(valid_blocks.values(), key=functools.cmp_to_key(self.comparator))
            sorted_list_1 = [x.get_block_str() for x in sorted_list]
        return sorted_list_1

    # returns -1 if time of item1 is less than, 0 if equal to, 1 if greater than, time of item2
    def comparator(self, item1,item2):
        if float(item1.get_time()) < float(item2.get_time()):
            return -1
        elif float(item1.get_time()) == float(item2.get_time()):
            return 0
        else:
            return 1

    # Get the time from the last block added
    def get_last_block_time(self):
        if self.last_block_added is None:
            return 0
        else:
            return float(self.last_block_added.get_time())

    # returns true if the message already exists in the blockchain
    def message_exists(self, message_to_check):
        if self.get_genesis_block() is None:
            return False
        else:
            return message_to_check.get_signature() in self.all_messages_by_signature

    # return block given its hash
    def find_from_hash(self, block_hash):
        if block_hash in self.all_blocks_by_hash:
            return self.all_blocks_by_hash[block_hash]
        else:
            return None


class Block:

    """An object to store each block in the blockchain

    Args:
        nonce (str):    Some hexlified nonce value
        parent_hash (str):  The hexdigest of the parent hash
        time (str): Time block was created
        miner (str):    The thing Matt wanted
        messages (list[Messages]):  List of the messages in this block
    """
    def __init__(self, nonce, parent_hash, time, miner_id, messages):
        self.nonce = nonce
        self.parent_hash = parent_hash
        self.miner_id = miner_id
        self.message_str = messages
        self.messages = []
        self.time = time
        for mess in self.message_str:
            mess_list = mess.split("&")
            mess_list[1] = mess_list[1].split(":")
            self.messages.append(Message(mess_list[0], mess_list[1], mess_list[2], self))

        self.parent_block = None
        self.root_node = None
        self.children = []

        self.level = 0

        self.hash = None

    def get_messages_objects(self):
        return self.messages

    def get_messages(self):
        return self.message_str

    def get_nonce(self):
        return self.nonce

    def get_parent_hash(self):
        return self.parent_hash

    def get_time(self):
        return self.time

    def get_miner_id(self):
        return self.miner_id

    def set_parent(self, new_parent):
        self.parent_block = new_parent

    def get_parent(self):
        return self.parent_block

    def add_child(self, child_to_add):
        self.children += [child_to_add]

    def get_children(self):
        return self.children

    def set_hash(self, hash_string):
        self.hash = hash_string

    def get_hash(self):
        if self.hash is None:
            block_string = self.get_block_str()
            block_hash = hashlib.sha512(block_string.encode())
            self.hash = block_hash.hexdigest()
            return self.hash
        else:
            return self.hash

    def set_root_node(self, new_root):
        self.root_node = new_root

    def get_root_node(self):
        return self.root_node

    # return true if self == other_block
    def is_equal(self, other_block):
        if other_block is None:
            return False
        else:
            # if two blocks are truly the same they will have the same block string
            return self.get_block_str() == other_block.get_block_str()

    def set_level(self, new_level):
        self.level = new_level

    def get_level(self):
        return self.level

    def get_block_str(self):
        return self.get_nonce() + "|" + self.get_parent_hash() + "|" + \
         self.get_miner_id() + "|" + self.get_time() + "|" + "|".join(self.get_messages())

class Message:

    """An object to store each message in the blockchain

    Args:
        pub_key (str):  Public key pem of sender, hexlified
        msg_body (str):  The message body: timestamp + : + encoded, hexlified message
            if message is private: timestamp + : + encrypted, hexlified message + : + receiver pub key
        signature (str):  Digital signature of the message body (use pub key sender), hexlified.
        block_container (Block): The block which houses this message, if any.
    """
    def __init__(self, pub_key, msg_body, signature, block_container):
        self.pub_key = pub_key
        self.msg_body = msg_body
        self.signature = signature
        self.block_container = block_container

    def get_level(self):
        return self.block_container.get_level()

    def get_pub_key(self):
        return self.pub_key

    def get_msg_body(self):
        return self.msg_body

    def get_signature(self):
        return self.signature

    def is_equal(self, other_message):
        if self.toString() == other_message.toString():
            return True
        return False

    def toString(self):
        return self.pub_key + "&" + self.msg_body + "&" + self.signature
