#Author: Elizabeth Ricci, Jonathan Kimber and Lam Ngo

import queue
import threading
import logging
import traceback, sys
from blockchain_constants import *
from binascii import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import hashlib
import hmac
import os
import time
from blockchain_objects import *

class Blockchain:

    '''Responsible for initializing a block chain object.  It currently
    takes no parameters, and does nothing, you'll want to change that.
    This object is created by blockchain_bbs.py.

    '''
    def __init__(self):

        # Use this lock to protect internal data of this class from
        # the multi-threaded server.  Wrap code modifies the
        # blockchain in the context "with self.lock:".  Be careful not
        # to nest these contexts or it will cause deadlock.
        self.loading_ledger = True
        self.run = True
        self.message_lock = threading.Lock()
        self.block_lock = threading.Lock()
        self.add_block_lock = threading.Lock()
        self.adding_block_str_lock = threading.Lock()

        self.bc_log = self.make_logger()

        self.message_queue = queue.Queue()
        self.block_mined_queue = queue.Queue()
        self.new_block_mined = False
        self.new_block = None

        self.public_key, self.private_key, self.pubhex, self.privhex = self.get_keys("public_keys.pem", "private_keys.pem")

        self.our_miner_id = hashlib.sha256(self.public_key).hexdigest()
        self.bc_log.warning("Our miner id: " + self.our_miner_id)
        self.current_messages_objects = [] #current message being mined
        self.ledger = Ledger(self.private_key, self.pubhex)

        self.latest_time = self.ledger.get_last_block_time()
        self.bc_log.warning("Time of last ledgered block is: " + str(self.latest_time))

        self.bc_log.warning(self.our_miner_id)
        self.bc_log.warning("=========== Blockchain logging started ==========")

    '''Returns the number of messages that are queued to be processed by
    the blockchain.  This function is called by networking.py.
    '''
    def get_message_queue_size(self):
        with self.message_lock:
            if self.message_queue is None:
                return 0
            return self.message_queue.qsize()


    '''Takes a string containing a message received by the server from a
    peer or a user.  The message may be illformed, a duplicate, or
    invalid.  If this is not the case, add it message to the queue of
    messages to be processed into the blockchain, and return True.
    Otherwise, return False.  This function is called by
    networking.py.

    '''
    def add_message_str(self, msg_str):
        self.bc_log.warning("Received new message")

        # parse the message
        # split into the 3 parts
        msg_list = msg_str.split("&")
        if len(msg_list) != 3:
            self.bc_log.warning("Message illformed, message will not be added")
            return False

        # public key of sender
        pub_key_sender = msg_list[0]

        # message body
        msg_body = msg_list[1]

        # split body into 2/3 parts
        msg_body_list = msg_body.split(':')

        if len(msg_body_list) != 2 and len(msg_body_list) != 3:
            self.bc_log.warning("Message body illformed, message will not be added")
            return False

        # digital signature of message body using private key of sender, hexlified
        signature = msg_list[2]

        pub_key_sender_obj = serialization.load_pem_public_key(unhexlify(pub_key_sender), backend=default_backend())

        try:
            pub_key_sender_obj.verify(unhexlify(signature), msg_body.encode('utf-8'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except InvalidSignature:
            self.bc_log.warning("Message signature cannot be verified, message will not be added")
            return False

        #check if message is duplicate
        mess_object = Message(pub_key_sender,msg_body,signature, None)
        if self.ledger.message_exists(mess_object):
            self.bc_log.warning("Message already exists in ledger, message will not be added")
            return False
        #check in messages being mined
        if len(self.current_messages_objects) > 0:
            for i in self.current_messages_objects:
                if mess_object.is_equal(i):
                    self.bc_log.warning("Message already in queue, message will not be added")
                    return False

        #check in messages in queue
        messages_in_queue = self.message_queue.queue
        for i in messages_in_queue:
            if mess_object.is_equal(i):
                self.bc_log.warning("Message already in queue, message will not be added")
                return False

        # add to queue but don't mess up queue (?)
        with self.message_lock:
            self.message_queue.put_nowait(mess_object)

        self.bc_log.warning("Message well formed and valid, message added to queue")
        return True



    '''Takes a string containing a block received by the server from a
    peer or a user.  The block may be illformed, invalid, refer to
    non-existant previous block, or be a duplicate.  If this is not
    the case, add it to the blockchain and return True.  (This node's
    mining may be interrupted, if this new block supercedes the
    current block.)  Otherwise, return False.  This function is called
    by networking.py.

    '''
    def add_block_str(self, block_str):
        with self.add_block_lock:
            self.bc_log.warning("Received new block to add")
            # parse the block

            try:
                block_list = block_str.split("|")

                # First check: check to see if it has MSGS_PER_BLOCK valid posts
                if len(block_list) != MSGS_PER_BLOCK + 4:
                    # Does not pass first check
                    self.bc_log.warning("Block illformed, block will not be added")
                    return False

                # hexlified nonce of 64 bits
                nonce = block_list[0]

                # hash of parent block
                given_parent_hash = block_list[1]

                # time block created
                block_time = block_list[3]

                try:
                    a = float(block_time)
                except:
                    self.bc_log.warning("Block illformed, block will not be added")
                    return False

                # identity of miner
                miner_id = block_list[2]
                # valid posts, should be MSGS_PER_BLOCK of them
                # store them in list
                posts = [0] * MSGS_PER_BLOCK
                for i in range(MSGS_PER_BLOCK):
                    posts[i] = block_list[4+i]

                # create a block object given the current information
                current_block = Block(nonce, given_parent_hash, block_time, miner_id, posts)
            except Exception as e:
                self.bc_log.warning(e)

            # get the hash of the current block
            try:
                computed_block_hash = current_block.get_hash()
            except:
                self.bc_log.warning("FAILED TO GET BLOCK'S HASH")
                self.bc_log.warning(e)
            # Second check: Check valid Nonce

            try:
                if computed_block_hash[:PROOF_OF_WORK_HARDNESS] != "0" * PROOF_OF_WORK_HARDNESS:
                    # Does not pass second check
                    self.bc_log.warning("Block nonce incorrect, missing valid proof of hard work")
                    return False
            except Exception as e:
                self.bc_log.warning(e)

            # check if it is refering to the correct parrent block
            try:
                parent_blocks = self.ledger.get_last_blocks()
                # if no parent blocks and given parent hash is all 0s, then it is the true genesis
                if parent_blocks is None and given_parent_hash == "000000000000000000000000000000000000":
                    self.new_block = current_block
                    self.new_block_mined = True
                    self.ledger.add_block(current_block, None)
                    self.ledger.add_to_ledger(current_block)
                    self.latest_time = self.ledger.get_last_block_time()
                    self.bc_log.warning("Block will be added as the Genesis block")
                    return True
                elif parent_blocks is None:
                    self.bc_log.warning("Block received, but block chain has not been rebuilt.")
                    return False
            except Exception as e:
                self.bc_log.warning(e)

            try:
                if self.ledger.find_from_hash(given_parent_hash) is None:
                    self.bc_log.warning("Block has no parent, orphans aren't allowed round here")
                    return False
            except Exception as e:
                self.bc_log.warning(e)

            # try:
            #     # Check if any of the new messages have already been added to the block chain
            #     for mess in current_block.get_messages_objects():
            #         if self.ledger.message_exists(mess):
            #             mess = self.ledger.all_messages_by_signature[mess.get_signature()]
            #             break
            # except Exception as e:
            #     self.bc_log.warning(e)
            # Third check: Check to see if it is a duplicate in the current block chain
            try:
                if not self.ledger.block_exists(current_block):
                    try:
                        if float(current_block.get_time()) < float(self.ledger.find_from_hash(given_parent_hash).get_time()):
                            self.bc_log.warning("Time Exception")
                            return False
                    except Exception as e:
                        self.bc_log.warning(e)

                    # DON'T CHECK THAT WE'RE AT THE BOTTOM BECAUSE WHY THE FUCK WOULD WE
                    self.new_block = current_block
                    self.new_block_mined = True
                    self.ledger.add_block(current_block, self.ledger.find_from_hash(given_parent_hash))
                    self.ledger.add_to_ledger(current_block)
                    self.latest_time = self.ledger.get_last_block_time()

                    self.bc_log.warning("Block well formed and valid, block added to the chain")
                    return True
                else:
                    self.bc_log.warning("Duplicate block received, block not added to the chain")
                    return False
            except Exception as e:
                self.bc_log.warning(e)

    '''Return the string encoding of a newly mined block if it exists, and
    otherwise returns None.  This function should return immediately
    and not wait for a block to be mined.  This function is called by
    networking.py.

    '''
    def get_new_block_str(self):
        with self.block_lock:
            if self.block_mined_queue is None:
                return None
            else:
                if self.block_mined_queue.qsize() > 0:
                    self.bc_log.warning("Sending new block to server")
                    return self.block_mined_queue.get_nowait()
                else:
                    return None


    '''Returns a list of the string encoding of each of the blocks in this
    blockchain, including ones not on the main chain, whose timestamp
    is greater then the parameter t.  This function is called by
    networking.py.

    '''
    def get_all_block_strs(self, t):

        return self.ledger.get_blocks_after(t)


    '''Waits for enough messages to be received from the server, forms
    them into blocks, mines the block, adds the block to the
    blockchain, and prepares the block to be broadcast by the server.
    The mining of a block may be interrupted by a superceding
    add_block_str() call.  In this case the miner should does its best
    to move on to mine another block and not lose any messages it was
    previous attempting to mine.  This process repeats forever, and
    this function never runs.  This function is called in
    blockchain_bbs.py as a new thread.

    '''
    def mine(self):

        last_written_time = time.time()

        while True:
            parent_hash_list = self.ledger.get_last_blocks()
            if parent_hash_list is not None and not self.loading_ledger:
                # when number of messages in queue == MSGS_PER_BLOCK do:
                if self.get_message_queue_size() >= MSGS_PER_BLOCK:

                    self.bc_log.warning("Sufficient messages received, block mining will begin")
                    current_messages = []
                    self.current_messages_objects = []
                    while not self.new_block_mined:
                        # Get messages from queue

                        with self.message_lock:
                            while len(current_messages) < MSGS_PER_BLOCK:
                                self.current_messages_objects += [self.message_queue.get_nowait()]
                                current_messages += [self.current_messages_objects[-1].toString()]

                        # hash with sha256 and take hexdigest
                        parent_hash = parent_hash_list[0].get_hash()
                        #  hexdigest of applying hashlib.sha256 to the miner's public key in pem format
                        # messages from queue, seperated by "|"
                        posts = "|".join(current_messages)
                        not_enough_work = True
                        while not_enough_work and not self.new_block_mined:
                            nonce = os.urandom(64)
                            cur_time = str(time.time())
                            block_str = hexlify(nonce).decode() + "|" + parent_hash + "|" + self.our_miner_id + "|" + cur_time + "|" + posts
                            computed_block_hash = self.get_block_hash(block_str.encode('utf-8')).hexdigest()
                            not_enough_work = computed_block_hash[:PROOF_OF_WORK_HARDNESS] != "0" * PROOF_OF_WORK_HARDNESS
                        # broadcast block.
                        with self.block_lock:
                            if not self.new_block_mined and not not_enough_work:
                                self.block_mined_queue.put_nowait(block_str)
                                self.bc_log.warning("Adding block to new block queue")
                                new_block = Block(hexlify(nonce).decode(),parent_hash,cur_time,self.our_miner_id,posts.split("|"))
                                self.ledger.add_block(new_block, self.ledger.find_from_hash(parent_hash))
                                self.ledger.add_to_ledger(new_block)
                                self.bc_log.warning("Blocked added to ledger")


                    if self.new_block_mined:
                        self.bc_log.warning("Interrupted from mining")
                        with self.message_lock:
                            new_block_messages = self.new_block.get_messages_objects()

                            try:
                                # check with the queue
                                for i in new_block_messages:
                                    messages_in_queue = self.message_queue.queue
                                    a_queue = queue.Queue()
                                    for j in messages_in_queue:
                                        if not i.is_equal(j):
                                            a_queue.put_nowait(j)
                                    self.message_queue = a_queue
                            except Exception as e:
                                print(e)

                            try:
                                # keep messages that we haven't seen
                                for i in self.current_messages_objects:
                                    test = False
                                    for j in new_block_messages:
                                        if i.is_equal(j):
                                            test = False
                                        else:
                                            test = True
                                        if not test:
                                            break
                                    if test:
                                        self.message_queue.put_nowait(i)
                            except Exception as e:
                                print(e)
                            self.new_block_mined = False

                if self.new_block_mined:
                    with self.message_lock:
                        new_block_messages = self.new_block.get_messages_objects()

                        try:
                            # check with the queue
                            for i in new_block_messages:
                                messages_in_queue = self.message_queue.queue
                                a_queue = queue.Queue()
                                for j in messages_in_queue:
                                    if not i.is_equal(j):
                                        a_queue.put_nowait(j)
                                self.message_queue = a_queue
                        except Exception as e:
                            print(e)
                        self.new_block_mined = False

    def get_block_hash(self, encoded_input_string):
        return hashlib.sha512(encoded_input_string)

    # apply hashlib256 to miner's pub key in pem format
    # Take hexdigest
    def get_miner_hash(self, encoded_input_string):
        return hashlib.sha256(encoded_input_string).hexdigest()

    # returns a public key object and private key object
    # given the public key file and private key file
    def get_keys(self, public_key_file, private_key_file):
        try:
            with open(public_key_file, "rb") as pub_file:
                pub_file_text = pub_file.read()
                pub_delim = b"-----END PUBLIC KEY-----\n"
                pub_delim_index = pub_file_text.find(pub_delim) + len(pub_delim)
                pub_key_str = pub_file_text[:pub_delim_index]
                pub_key_hex = hexlify(pub_key_str)
                # pub_key = serialization.load_pem_public_key(pub_key_str, backend=default_backend())
        except:
            self.bc_log.warning("Error: Public key file in invalid format")
            exit()

        try:
            with open(private_key_file, "rb") as priv_file:
                priv_file_text = priv_file.read()
                priv_delim = b"-----END PRIVATE KEY-----\n"
                priv_delim_index = priv_file_text.find(priv_delim) + len(priv_delim)
                priv_key_str = priv_file_text[:priv_delim_index]
                priv_key_hex = hexlify(priv_key_str)
                priv_key = serialization.load_pem_private_key(priv_key_str, password=None, backend=default_backend())
        except:
            self.bc_log.warning("Error: Private key file in invalid format")
            exit()

        return pub_key_str, priv_key, pub_key_hex, priv_key_hex

    def make_logger(self):
        # Set up logging.
        # create logger with 'spam_application'
        bc_log = logging.getLogger('Blockchain')
        bc_log.setLevel(logging.DEBUG)
        # create file handler which logs even debug messages
        fh = logging.FileHandler('miner.log')
        fh.setLevel(logging.DEBUG)
        # create console handler with a higher log level
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        # create formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # add the handlers to the logger
        bc_log.addHandler(fh)
        bc_log.addHandler(ch)

        return bc_log
