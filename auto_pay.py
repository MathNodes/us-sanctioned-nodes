#!/bin/env python3

import argparse
import scrtxxs
import requests
import sys
from os import path
from urllib.parse import urlparse
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins

from sentinel_sdk.sdk import SDKInstance
from sentinel_sdk.types import TxParams
from sentinel_sdk.utils import search_attribute
from keyrings.cryptfile.cryptfile import CryptFileKeyring
from sentinel_protobuf.cosmos.base.v1beta1.coin_pb2 import Coin
import ecdsa
import hashlib
import bech32
from mospy import Transaction
from grpc import RpcError

from datetime import datetime

MNAPI = "https://api.sentinel.mathnodes.com"
NODEAPI = "/sentinel/nodes/%s"
GRPC = scrtxxs.GRPC
SSL = True
VERSION = 20240603.2209

class SanctionedPay():
    def __init__(self, keyring_passphrase, wallet_name, seed_phrase = None):
        self.wallet_name = wallet_name
        
        if seed_phrase:
            seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
            bip44_def_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.COSMOS).DeriveDefaultPath()
            privkey_obj = ecdsa.SigningKey.from_string(bip44_def_ctx.PrivateKey().Raw().ToBytes(), curve=ecdsa.SECP256k1)
            pubkey  = privkey_obj.get_verifying_key()
            s = hashlib.new("sha256", pubkey.to_string("compressed")).digest()
            r = hashlib.new("ripemd160", s).digest()
            five_bit_r = bech32.convertbits(r, 8, 5)
            account_address = bech32.bech32_encode("sent", five_bit_r)
            print(account_address)
            self.keyring = self.__keyring(keyring_passphrase)
            self.keyring.set_password("meile-bounty", wallet_name, bip44_def_ctx.PrivateKey().Raw().ToBytes().hex())
        else:
            self.keyring = self.__keyring(keyring_passphrase)
        
        private_key = self.keyring.get_password("meile-bounty", self.wallet_name)
        
        grpcaddr, grpcport = urlparse(GRPC).netloc.split(":")
        
        self.sdk = SDKInstance(grpcaddr, int(grpcport), secret=private_key, ssl=SSL)
        
        self.logfile = open(path.join(scrtxxs.KeyringDIR, "sanctioned.log"), "a+")
        
        now = datetime.now()
        self.logfile.write(f"\n---------------------------{now}---------------------------\n")
        
    def __keyring(self, keyring_passphrase: str):
        kr = CryptFileKeyring()
        kr.filename = "keyring.cfg"
        kr.file_path = path.join(scrtxxs.KeyringDIR, kr.filename)
        kr.keyring_key = keyring_passphrase
        return kr   
    
    def __check_if_node_is_active(self, node):
        try: 
            resp = requests.get(MNAPI + NODEAPI % node)
            nodeJSON = resp.json()
            
            if nodeJSON['node']['status'] == "inactive":
                self.logfile.write("[sp]: Node is inactive, not paying...\n")
                return {"active" : False, "addr" : None}
            
            resp = requests.get(nodeJSON['node']['remote_url'] + "/status", verify=False)
            return {"active" : True, "addr" : resp.json()['result']['operator']}
        except Exception as e:
            print(f"[sp]: {str(e)}")
            self.logfile.write(f"[sp]: {str(e)}\n")
            return False
        
    def __get_balance(self, address):
        CoinDict = {'dvpn' : 0, 'scrt' : 0, 'dec'  : 0, 'atom' : 0, 'osmo' : 0}
        #CoinDict = {'tsent' : 0, 'scrt' : 0, 'dec'  : 0, 'atom' : 0, 'osmo' : 0}
        endpoint = "/bank/balances/" + address
        try:
            r = requests.get(MNAPI + endpoint)
            coinJSON = r.json()
        except:
            return None
            
        print(coinJSON)
        try:
            for coin in coinJSON['result']:
                if "udvpn" in coin['denom']:
                    CoinDict['dvpn'] = int(coin['amount']) 
        except Exception as e:
            print(str(e))
            return None
        return CoinDict
    
    def SendBounty(self, amt, node):
        self.logfile.write("[sp]: Checking if node is still active...\n")
        
        result = self.__check_if_node_is_active(node)
        
        if not result['active']:
            self.logfile.write(f"[sp]: node: {node} is inactive.\n")
            return False
        
        addr = result['addr']
        self.logfile.write(f"[sp]: {addr}\n")
        self.logfile.write(f"[sp]: node: {node} is active. Commencing bounty payment...\n")
        balance = self.__get_balance(self.sdk._account.address)
        bounty_balance = int(balance.get("dvpn", 0))
        if bounty_balance < int(amt):
            self.logfile.write(f"[sp]: Balance is too low, required: {amt}udvpn, found: {bounty_balance}udvpn\n")
            return False
        
        tx_params = TxParams(
            gas=150000,
            gas_multiplier=1.15,
            fee_amount=15000,
            denom="udvpn"
        )

        tx = Transaction(
            account=self.sdk._account,
            fee=Coin(denom=tx_params.denom, amount=f"{tx_params.fee_amount}"),
            gas=tx_params.gas,
            protobuf="sentinel",
            chain_id="sentinelhub-2",
            memo=f"Meile & SentinelGrowthDAO U.S. Sanctioned Sentinel Node Bounty",
        )
        
        tx.add_msg(
            tx_type='transfer',
            sender=self.sdk._account,
            receipient=addr,
            amount=amt,
            denom="udvpn",
        )
        
        self.sdk._client.load_account_data(account=self.sdk._account)
        
        if tx_params.gas == 0:
            self.sdk._client.estimate_gas(
                transaction=tx, update=True, multiplier=tx_params.gas_multiplier
            )

        tx_height = 0
        try:
            tx = self.sdk._client.broadcast_transaction(transaction=tx)
            
        except RpcError as rpc_error:
            details = rpc_error.details()
            print("details", details)
            print("code", rpc_error.code())
            print("debug_error_string", rpc_error.debug_error_string())
            self.logfile.write("[sp]: RPC ERROR. ")
            return False
        
        if tx.get("log", None) is None:
            tx_response = self.sdk.nodes.wait_for_tx(tx["hash"])
            tx_height = tx_response.get("txResponse", {}).get("height", 0) if isinstance(tx_response, dict) else tx_response.tx_response.height
            
            message = f"Succefully sent {amt}udvpn at height: {tx_height} for sanctioned node: {node}." if tx.get("log", None) is None else tx["log"]
            self.logfile.write(f"[sp]: {message}\n")
            return True
        

if __name__ == "__main__":
    
    
    parser = argparse.ArgumentParser(description="Meile Sanctioned Auto-Pay - v0.1 - freQniK")
    
    parser.add_argument('--seed', action='store_true',help='set if you are specifying a seedphrase', default=False)
    parser.add_argument('--amount', help="amount to pay bounty address", metavar="udvpn")
    #parser.add_argument('--address', help="sentintel address to send the bounty amount to", metavar="sent...")
    parser.add_argument('--node', help="sentnode... address. required to verify node is active to receive bounty", metavar="sentnode...")
    args = parser.parse_args()
    
    
    if not args.amount or not args.node:
        parser.print_help()
        sys.exit(1)
    
    
    if args.seed:
        sp = SanctionedPay(scrtxxs.HotWalletPW, scrtxxs.WalletName, scrtxxs.WalletSeed)
    else:
        sp = SanctionedPay(scrtxxs.HotWalletPW, scrtxxs.WalletName, None)
        
    if sp.SendBounty(args.amount, args.node):
        sp.logfile.write("[sp]: Success.\n")
    else:
        sp.logfile.write("[sp]: Failed.\n")