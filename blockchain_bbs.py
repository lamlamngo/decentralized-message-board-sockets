#!/usr/bin/env python3

import hashlib
import threading
from blockchain import *
from network import *
from blockchain_constants import *
import threading


def main():

    blockchain = Blockchain()
    blockchain_thread = threading.Thread(target=blockchain.mine)

    blockchain_thread.start()

    server = Server(blockchain, True, True, True)

    # Main thread is server thread
    # This call never returns
    server.run()


main()
