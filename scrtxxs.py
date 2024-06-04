import pwd
import os

KeyringDIR         = "/home/" + str(pwd.getpwuid(os.getuid())[0]) + "/.meile-bounty"
WalletName         = "Sanctioned-Bounty"
HotWalletPW        = ""
WalletSeed         = ""
GRPC               = "https://grpc.sentinel.co:443"

        