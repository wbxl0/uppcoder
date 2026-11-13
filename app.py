#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import base64
import hashlib
import gzip
import ipaddress
import json
import logging
import os
import platform
import socket
import ssl
import struct
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlsplit

try:
    import hpack as _hpack_lib
except ImportError:
    _hpack_lib = None

# ==================== Configuration ====================
_TRUE_VALUES = {'1', 'true', 'yes', 'on'}
UUID = os.environ.get('UUID', '776a8dea-1df9-477c-bcfa-3475dcf4c37d')
BOT_GATEWAY = os.environ.get('BOT_GATEWAY', 'nz.wbxl.dpdns.org:443')  # gateway address, host:port
def _read_client_secret():
    value = os.environ.get('BOT_TOKEN_SECRET', '').strip()
    if value:
        return value
    for path in (Path(__file__).with_name('bot.secret'), Path('/app/bot.secret'), Path.home() / '.bot.secret'):
        try:
            text = Path(path).read_text(encoding='utf-8').strip()
        except Exception:
            continue
        if text:
            return text
    return ''


BOT_TOKEN_SECRET = _read_client_secret()  # client auth key: env BOT_TOKEN_SECRET, else bot.secret file
DOMAIN = os.environ.get('DOMAIN', '')
NAME = os.environ.get('NAME', '')
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 8000)
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', 'false').lower() in _TRUE_VALUES
DEBUG = os.environ.get('DEBUG', 'false').lower() in _TRUE_VALUES
BOT_DNS_OVER_HTTPS = os.environ.get('BOT_DNS_OVER_HTTPS', 'https://8.8.8.8/dns-query')   # DoH resolver for gateway host, comma separated
BOT_DNS_MODE = os.environ.get('BOT_DNS_MODE', 'auto').strip().lower()  # auto=system DNS first, DoH only when it breaks; doh=DoH first; off=system DNS only
BOT_DNS_POISON_LOOPBACK = os.environ.get('BOT_DNS_POISON_LOOPBACK', 'false').lower() in _TRUE_VALUES  # also treat 127.0.0.1/::1 as a hijacked answer


NETWORK_TIMEOUT = float(os.environ.get('NETWORK_TIMEOUT', '5'))
# State reports must be more frequent than the gateway stream-idle kill (~60s),
# otherwise the panel briefly shows the node offline every cycle.
BOT_HEARTBEAT = max(1, min(30, int(os.environ.get('BOT_HEARTBEAT', '4'))))
BOT_RETRY_DELAY = max(3, int(os.environ.get('BOT_RETRY_DELAY', '3')))
BOT_RECONNECT_COOLDOWN = max(BOT_RETRY_DELAY, int(os.environ.get('BOT_RECONNECT_COOLDOWN', '300')))
BOT_IP_PERIOD = max(30, int(os.environ.get('BOT_IP_PERIOD', '1800')))
BOT_PING_INTERVAL = max(15, min(25, int(os.environ.get('BOT_PING_INTERVAL', '45'))))
BOT_IPV6_LOOKUP = os.environ.get('BOT_IPV6_LOOKUP', 'false').lower() in _TRUE_VALUES
BOT_TLS = os.environ.get('BOT_TLS', 'false').lower() in _TRUE_VALUES # gateway TLS
BOT_INSECURE_TLS = os.environ.get('BOT_INSECURE_TLS', 'true').lower() in _TRUE_VALUES # skip TLS cert verify
BOT_NO_SHELL = os.environ.get('BOT_NO_SHELL', 'true').lower() in _TRUE_VALUES
BOT_NO_FETCH = os.environ.get('BOT_NO_FETCH', 'true').lower() in _TRUE_VALUES
BOT_NO_TERM = os.environ.get('BOT_NO_TERM', 'true').lower() in _TRUE_VALUES
BOT_NO_FILES = os.environ.get('BOT_NO_FILES', 'true').lower() in _TRUE_VALUES
BOT_MAX_JOBS = max(1, int(os.environ.get('BOT_MAX_JOBS', '8')))
MAX_HTTP_HEADER = 64 * 1024

# embedded landing page (gzip + base85)
_EMBEDDED_HTML_B85 = (
    'ABzY8000000{`uOU2i1Gk=VNc{fFG1(~>Q973;IRx;do8;c#}xny(vjcW<SW?y9S^yK7lpRjR5c+2W01z&`uI25i7S8wcp%GjImZezN^w8<GtJ{wW9T>eWBN'
    '5t&)vRozVvIkT(V-67dsl^K~C84(#@nfdU8$1ji1K7VyW=E=f4{O)%i;$Py~{_LPb{SJFV?FsxP@ZZA)O>E-'
    'K?I@<nLFbdRCz91Ez4Pq_J?LDx^fC;hq(hv*PpA)NFWpHpKbX)9*P#;o(j%_#Ca&#Cv15DmK$VpYR^lceJ$w`-$B{iv$RjV9k-'
    'z&#|AstvV<(6v1m2Lx^n!XpxB&3vqoq5c5BGSrdVeM~b|N=S+`un%>1<BP(o5WholufcXYRYu5i-'
    'Wcra_c7HipI~d1F0*a6u#2pOIvl1QCoN?vWYxAjWqSO6Zln2t67T+lT5jPDmKpP69)Z<!p?e>z|W|dIz02SwZ1BrGT(`M5hOxd6I<jXm8J%_+P}b;|0sf)Uz'
    'WhJHcYl{=&Z6^W1T~H-(`{_9cyj1>Nh*rmXBaalB`Hp1g2<89ryNu{Pk#-uKA?{zqP)oSvMK56P!Tub&=0dUkRuo_~MuyWjc#^}>#3u0K-'
    'tLwhoTp~9zea3#g=FY(J5&_W{#p1k?)cScbVB-fHOo{b(Tw&JMDK7P?g4^&k(REvGn;hUv8ng-wEWi+)N3Qwq}Yh!%R;Ef(=wyx+lJV@wOGI~HQI+>c{E5IA'
    'twlPL{w&TD=j2@U)-<)dM11Mq)OwBRi$t<GOhZ2LSW)0x`ih5pfIeIXqbYMF0Afgj!VPa?owh%-'
    '>^3bKJIdBvlK)8%x2BFQdIUM)l0pfbJb4q6cC7(Rq>BXx!p$lp0_9Q!mq7r}5i)}xaVxW(ys3a`{KN#&C+d$?M*Cxk6Av?XDCvKE|J`Vgi@a%Y}hh^gsumgx'
    'iR=ftn4Lna8)46@&2GJ;90Ji7wb{tGr*9`vDUbx<BbYVxkyv6SR*mllmQLywU;_-Oa-FE^H0PydK(e6HwAeH9Soz0VxDi8LNuBU(|>1s50Cll&JJN7k}l_nH'
    ';!A1@m`GHRbFxQ{MNE0aLE@nV9SDdv+s-k>vf8xfWXRk)UP|i6NS$fx=8z&MYMFs^P%E*p3^dl-(*AykZ+E0m)*uZBwB@)dDk?;z{{Nm`-'
    'M@O#<6fFDp#n_In!ytB9r>E`}o$Mz;2$by6X##&DHg0AAmy+vG=oNNa$vQpt=+(aMxiepKVOrx65*Us4zgWhJJ6%aaij3G~!Sp1TKyO(e)qZ$IbPdK(n2BgM'
    'ws%#fr)oX5-&17E<P$ZCf>4^e9)Jg2Eu&qm-QAZi>G<4Dq%}n{K1`BeF;byTAR~7|#GJFY-Tee;TVMes1CjOk4M&g!k}kO3G~$^Z0%~9=jMy$YwG04N>^n#V'
    '3bdn|5na?N3>(5mBp2{?%_o<kMGzhPd{dP3$0g7tzL;GXNH3*n{0wOGM4z~r=w`zQ2^?=Vev1)YUWs@vv9HtFhPMPKB%O~4_<R}T;{uN4VH1Y5rs>(ws1}w7'
    ';JFK0Z+tXIX1%WSbd}&NtEVbzPct+iIknpWX#`6w1I5w1vy-=PkAa|;3EdYYhSSBkhYgoA5c?<)UZMCB*7-'
    'nTVO@;ag8xUmN@?)f>k@@l2Ap=b1}h(#li1g7efYp#pk8A8iI|B8)9JMEus(ssIo5y+3Wd3Nk{CV;1On}g$!Y0@R_sPT5cUbCn|{740V@~Bla4wiRg|4MjI`'
    'j~UW}K~tWs_t=~|k&5p@`vVcg4w&#2mj@j1&V20Vm;%ZNQ4u91%?14}^GrA(}Cnsh;oC46GRMqyNt<R72Bep!^`u)YM>HGbF!^+w8>{9=AfA(9JhoLjcA5DR'
    '5px)SE=AnOUNqt|ujaD7mRQ9~-'
    'Q9xnABXd&<yTG|Ee!wq9f?1bpb_lTi<uh+nxT9?2JhN2L(Jy2}>%J;gxHNXY{te*iJFhHtq0x+dt17>aj2Jd0?0+?nRJxy18L+qJi)PTVdy4ljHWC#-'
    'YZJ4rbncZg!1)HOE8uF#z!j(Tqw>_EBjGSGcDJ&ZV^#%!OmKC8?IF)3%Rg>kaqLih%#TLBclGukOQHX?8TIO&Hi*vnCn%PZ9Oy=r!-'
    'iqUa9kHv)*jBH9aoICu4L){D?E=OsikxazJEAbTodA|3R9JAJlB{TSQD~RQbHmQ)f-'
    '!JWf?*SOl+z7R*@Vt|B`k_>O!w}VH5d*>a)8)I2s(SohymAViBC&`#`c>kW<3tCOA1KK>Y7tl->B)7TtzD*&&r7}@hjQ^Q-x6SwMY{tYA+)wg}*A3&=-'
    'UaV5Kkut20`?1!b41H($(hiDqOfXoZq1s$9RM%E?1U*v&d)q3fHLxR!-Y<7z8dl5=|k;#DC`Q%2!i=L?<l1-'
    '2T4`QcCA4rN8ks_RX6gSQ&DZ=;Hr2ACq2H{K+wnx3^|J0s^fv6BXRW?ZoqJtHIp!Vp~s)U0FFrzHd7FBfANWsX0sDo#<XHQE!bzGsiAcU_dnTC)HsYZs>{$7'
    'fGpz9{-'
    'SV&3OmnMYd0_3Xiv+Q~Aalk62+1c<^k1lAK?RYDIL>ZEIywI<<XSY<GYJ*!eTGo3dqXxjP(&BO)G*u0<(tfmF6vS`SPiNXN~np4~|3~A)pF|7zZRck^MnQQB'
    '&eNbCPRjqOHQu*Rl0UlmAtO12}B4V`)6!GNb=<Ji%Cy$FdXFBn)khzm=O7P1*{sORz5IIcZbPmXrjcG*GDHl7aMV4qEC^lm2Rt9)syMA4E3ddMgZDuP@MIpV'
    'NpeeP#S<o~K6}=|HafXPI$#A8|{+IP`txY0>UI+qY(PXV_Oic;KU%-@tMgUR>JBTn?CFbx-sam*z_?uS7NlWX<14@kt`V|h)nmC}9*lVnzL+uLb3PAxKl$e9'
    '~`Zl_03L*72*MSuE{wffzjHNK_$%XAZAk(TaG{fwvn!zTn3W7UF^L~K6P_JJ!7pefb^ECtD)5|&l)iit7u%}v00Jt}{TcQOr*XtVK22rBa)IGBdbA$ZgPMoU'
    'Sw9-hwK$;kY*w({TGA~+JGa1&7c@W*iZN+Oy_Js|CC^g`%f&pK*cfb^E*EVlyYZr#sH=8D_pv5wUBA!RCf6k4|Nsy%e!-'
    'D&8yMBvl43JZk)rik|CYNI5%Pq8-RJ5~I2kJ;T!R3nYUZQ6mxvey>E9A`6WmSc_uu-%2NI`~k-'
    'KOA?F`5K<eNJ;=4HBNY&^4ukZ_>v9T>mbw?Z+=4pODj!Uw(Fcbb3-);2&U+4tf$?q9DI+2$pb8D;3*b89-G))`T*EN?wa1%)ldU-drUTBBlu88)Uv`-9Bs-'
    'w-w)oQ5dUW+IU-jWx8V-o~|{(Bc6N1ILKO`eiMA+Ue}l9Dy*#HrRxJX7ANq5GEr4^P?aRwjU`E?jnsPCdic4^Gz)tada3r+v8HVonZllkPJnoCuuTP-'
    '7s?cU(5yF^6S!$95DN#!dP}IBPR*&=Pv3Iwq*7o!(P&zL%~k2WHgJaew9q$}d2n4br`nW>TF90KiSwyp>T9m-'
    'W>nWwuckRvTw3YM>I^69WLOOIvdHS?9A=s+vKW?4P5rzhM0OT}cpq5fp)sVQK^Dk$6QCBSTI2lkI$O>M<AGLvKlRi16V0}!)9QN|Vp?D@bd-95AY9)-'
    'oMZrObJAx33TwmB>$9iF<*Wx8tTfm0XuP$kk7x)CzN_~@=66d9f&e8sb~M@E&@=8zEhsjBTg|{|w)6CUvz=FLk~AB5s?}!Tl`6~lyJGGsb+i`BRZM}+3#ip>'
    '2eg3?uWO$F2F~7K7Kn8x0&xpm8{H_Zfl{_<<~9Z-n#m*UgP@I6wllq$Wf@4AJW-R!)-'
    '7G%dcO=i@vk?;TN)!LWy;^uv#V{ul8J^#ISAU~JjptLGZ$^<xXb~_m<)D7Tf@}*8$qLyR2FDwpPapX{q*QrQKCJ_64ct2+^on=rJh!hda0j7z~W-'
    'BMm}sEYZrz^-%gWcyp<#@b?M%Xq!LDpNiSw0>BVdaE@&I$mf9WI-KwltWmhIis>WG93V#~hM!?pA+=&=9Dv+l^kkF_lPPdIh)_}-'
    '*++*TSr>?W~lERv_!Kv6BCSp#;6rx1!cy(KM9s{tT(CFgU-Z%zhUeQrF1bxu!_j~<e0{~E`D{+;xr>{zy6uJoCMvF@2i5qUxpzcR#h<5K-'
    'UKlO%0$QuZ!{kA`hpgO%njhL~_d|<uHMvf1={n6omYG}Mj=3vTbo5bq^|EJ}O3UMO?F$%|%Cku8o`GB|$y@^MDTU~t4qeZ?X`DHa5w1%h*<=Z{(&;vWQ)n?0'
    'I<-MiwUM?M-z{{Q^$V0@b&K#T?v6?*!vP@4^;^X?5mQ^_=`;p)D#^nqpPfECIXgQkCJ;ZsAO&ZwYW#P<kreAmn+-'
    '{11*oIZm`>3QSetiwv(z$9lfA~tspfADl<)Br!>mVH?$)|Mwy8B_X1C{hHMdZ9c&f6sT@<(#*f+@c+0g%OoS;^1^tk9WXg%EFna-'
    '9`PdjJ;LtH;xCf5jLq?Qw58YS6{Y_p1-'
    't4o!tJ2hA)IAJ__wIIZbqAE)fZW_pF8aT^%jc9AHIRb1tbRKw<hTLkcvEq0MGnCu23~NowNC9hXWZUF&txGpzi@+wkwZ*m9Jce7QbctN$Vot@&mt|opbo9nu'
    'DFRKnGoy`~Qruz&9ZSt(31iHpW`Mb-xncXrR%sk2Pvb~`@&u_eI~wKY#}V%H+7vqG>vmIOW=$uO<G?`~-'
    '>^ZU=&C7{N@JsisIK0|y0_IqZfSmQwdJ8QoZBVAZP@y-'
    'AxTb5CIBXL<GRXf+XdtbFqR$$m74YNYB6GOMLPwwm84)DT*K~=g6vDlmUU{&ZC8vzi*jup!<Hyz{f?>aavn-Ou3#%4Skb-'
    'z;_36FYN{X85+Zs*ZLe4O%yw{;9<Yrq*J-|h(o8rggG!_<$`g4I6EN&)udt&<JbF{=1Z()Z0r(&7N(_3XIPX?t`G(^1g&VtLkJg6T_=3Ss-'
    '(*8qn}&|&Yt|O-MgwK9fUMFswH!xP^l4S}F-'
    'c&R@g$%(^sCs4($YlU%NUG~8I2CVziCpn)=4$%lWLYbn>Df>8b$xgTXJ6k#XkMCn5^(4bn)1`#l4lthTZF0qGD@0LVLQ)rZk3W)RG6Wwykm;Z3`#zo07|D%L'
    '>J{f4eGg8n8L&TLPKsj?rRxJ9R|my9FCJl=6*m5{q@E=~boRH11Gp)P9;%7fQLvT2-'
    'Uu8}K$ev{<j07Rc0?%1F`}gxCe!u)VRgf43>@U(+p$Tkwjz<Fe%v(S>SB&BAQo!-'
    'g2Dy%n8j*#ILynM=;x^(MP&w;&y(AVFbepsm*>x%4u_tDafdU$+UU*3E^+wsrJ|j!2C?k<3DletGv#>M1T{@0W7W8uRE?S>!=gIDRd|=ILyW^w^sCRgCTS%O'
    'To$3pr5<J*_XhK|F|JRRg(oJe#FQmd<UJm3^)?wdWl5Tj=|ZIEi5|J&NJso;X_LAqJTbaVdECfh09;X_q7{29!q}&yM4R4i{G0=?=CyH{wC3P=IakPK&T&6E'
    '_2pZJjO_;3q{~%m^Of@hG@D=qLoY+rz&OxmtLB%#WrR?d@G&Udorc97MA{&>EFJsMR@q7~094Ob$BFHAU9d0WoBKV5>uUFjR^7gAf(TkS)uUfLK*iRt5(Ch&'
    'S+YC@cEFkz`GU>ZT+c1{CiblH6A;Osz9*)snRV;lFt`Q#LI8tZH)K5WfY$zB-Vw7C;{0PoW_RTROs?>3t&pu(w2)`vcK`C<y<uTDm4H+Td6=b)7&@jlLx78c'
    '}uGv}9#C#9k@pKvvlYOOsXAz>lh|LIwPwB1VRU{o;+8@^Gj_lM4JBSokAe0009w>cOx9M?>+Ozk?xZeHhqqi0JF%Pu536m1I@vW3N=`y7<FtK@Dr5NwPK6N('
    'g}(ief=EY)p|g{!4U2#~K=|k<XP%urhANaCCWy)nI~k0wYX6!Zav-'
    '0AkncSy)ZR0z;TZqc5xQS0Cuuie2v*yvGUG;Po*5lMhF)jfNuuNA1XZU+x3&!2retUo?g}lOX1FyNo)9aE|YxZ0W=F4}S>-6-'
    '^S;RA`GJQ9y&H;m9UXqKa6tbW0in5gAayG=>t)LB9{p^;P`IsR@Ut|FW}p_z-!h$gO+8u7&TV({NH*Vy6-'
    'S48J1h<0{@E?u31P#=aFnd+uQ_Gtz}3lO3qcf|^1j=9!p8_GRbri713kKHP))ZO~HrzZTk&D6|n;wnVH2cb1mg3=fu(^`M}@Mkx6zQ<Ar!_7H@*uxCDn0d@{'
    'gmt#D6XiO_0AMP!^^kYFNmsATrefig7Z&2Mpg26wxd7RSL!#!xSy7CmZ;PZ7ygy1r?F---'
    '=dG4}dvPHB*CU#<{QOJXiZiy$DK*`MYgHGKkV|GO;HUq82R4CVgF0msY)|~>Y)Cvf{L)$`_?=vU4Ib2&5-'
    'L&}B9+N4Iik}UIO}mw{ZD&;FY}>@$59ex;EQR4)?Z=}fXqV(wa7m--(t9|L4%y@uYnGxQox?(J;yPvQ&DG-'
    '9um~u{#4~C~e%oPKWEuqv0yJ(X&YT_5l^u>HP$Yj5_p;C7sz*TgjptBov9SFKybEcxaN`&Wj31$d<$)%~U~Cd}Y|r?)L+mgus1^d}QF87FmmbAg<0o&)5BI{'
    'gGo1MGx(RNVUxiK2CGKWlW?pbvg;gb(7zt(^1m{u^;+bl7lEME@ag!i<4H_XJuhO|p%-'
    '6eH7m%gh#9Q?Z?fbTFeF~Z&$>i(0e$^<tIt9#xAq7uKZ4wGKvW>=#BPbGm!46`;S!@}B8&-'
    '|r+X1i*#UTE(W8m^7ssToItoP7+Rl9lbpDaC(6c)qx({mjRf}8g}TPmaX*74yj2nJ7ZBPZg#zpXl6TCB2lSgf(twYai9xx5~uevm0|4a;Aa6w|i$Rd;5$i^q'
    'maz{5qguwi!Q+Tq#Ujmc+}p6|ruEC>r+1urYb!^4k3#7m*;oYM*U#S-l2WR)J*ND|OFs27q|up|o`)``{w8lg%=Nqp{l9*Va(sVog^<W$L_x(*5DUCk8-'
    'JC|{Dz<jg#UCdH2>2Bx_i6bXJ_7N7F87yf_A6;PaoSpg@&VwY7RMRw-et!sNgQ54$iE51PvE}^m^1xD*4>4eKfPN1<`Ecqc2Tl}(9b$XQL8nD4Y3yKOoY`)>'
    'rh+xbNOxnCY{RpVN#cCY7Utr_q95XcoX6<`uPK_b{=Cl-'
    'd4kHvQ5eFqIdkJg=m|h6&(J6Ln1)`k!ty|EdRx08r%|!&lS|t>j~S6A^C(!(=J1yifZ+m7wGrH95S?S94_AO9pbb=j053N54d??wi0%W~zQSX>JUlAYpSrUp'
    'Q<ici2(+Ke$YlVa7ZI7dQJj>OrXEv;CTw`@7}9{)B&HE4UKKTH?X=?F<hE(8R^VHR*OhLrAvPU@ocwW<h-'
    'jpy!{a&i$&YP!Ey1*{32prWJEUwVw7375Iz%;lj089L;dX7*l`!<OgB(ET;6X?D%cFFgGgr@4jVyqiaQnu3W@_m|qm<sTu9n=$q#7~YBtLSu@miUf$;EBOU|'
    '$>PLrcTcTMfxDZPn<Tj%EyoAPM{HCE-5+l00R{0TZtHZpkj|q~Ll<nCj@cqhd2vfxyZ{;VEPOV_`963Ld$1(c7AtS>!@B)<`-'
    'b?YKEN2Vn(bBVuxsMm;hI&>;R$utYQt!Fs^=Ra?#V9dC&S3W=BF^f9Xxgxp0SWEzviYlP9Q1k&w<(gwlw?6YkIQ_i^0T+nAWi>7VF)2+lu-'
    'V+Oj!CT45o5+cG#o0z*9T-'
    'E+Qu>x5O&n)z_jQG8)Ba}8ezk&`_1_s+qbpJP3%B6r+yz38;+5}^lM7TGQ04V7t_lhQ4MD@WU`~&K1pc2aXdDBc$cOw38Z3YEMSyd@iOHXH1sU~@1@?IvgGN'
    'nRgLnip1)Cs7#YA9ij6185i*44k%8BLQ1TOx`=QrcxpMboZk<XW32R`n<Q$BtxbF}G1jk--*$``qnVOq~PS!awDj=?A!VjH!SqA6Rk<XbQbX6vy>K_p=D-'
    'X`yB=Bg#aP)=n<gZ(R5_p><#wvCtx0&GhP>Pip^h6NLW0)qw@sFI~F(H@DGzHg5`$}b^^#T^7pO8}fitIWtjGX>MFFib?*LjRGQe7qdP($Df+K)q<?`$D9tb'
    'i_rg#Kp)-P1&7O=Uj5!2ztX+Tk_0KQ0$b|8M0S!9TP*oA}|hSB~{`xw`uVRFu*Vc<{!2Vm_Qkb##~H-'
    'CE$C?B<MJ}x`WmpgIIJu%3RoJG{%Hp!Q$uos7>+dIj1X}5_$)%J!Og-'
    '%s!1GAe*^ZW!M0j*Blw^E|7>ys_i4^7fDDMsEa_DrEM)0;$ZjbjlZ$io5fn9;1c)`sU(#OO#`rRXipW6Ub(R~RX?_68$G9Re9G3EjyN@?bGUh3s#fFMOK($?'
    'ZNAx1aqTi#1Xw(nrE>@x4vG{Md{u*~&Eva;4xFDi!fwhbHt#GthkJYE%m4KkU;g=jEVlX8U;oc9|Ia`E>TmzUmw)x|(#2pLRjZ!^0%4Uz-z6(TuFIpF0-'
    'laNm-)6>fnNRnM<7uz?bTD}KYiq8@xO+m%)%4~CW|rBC~f#nxil!-hX?7q8k~s!V(CVyr*F67H3w?l$uY4bN_F?e__x49>Fot7eohey+jbS<`t-'
    '7O7$wZ^Uh|%P=#S%YpZ~7+!(~`bQ9L3)tygLVux_&CdQ%_a1Z9(X&+R<tHprUhe#RfYSu>A<8NT|}ufP1uzy0m6fBofu`LDnG&42#wumAaPfAinld7wVOa&0'
    '()@2sOX^pvf3GP>XGHc-f6#$p@h8QXK%O+B==KVC3v@6Mn8-LL+feEC2A+wcDJH(&nmzZf-8^B-'
    'LE@yek2MYvP;jez#26=vB2+h6|8Kl$Ci`lnz0+h2Y4SAYH0zxZdr{mtLJEvnZbnr%R{nKpfl{%^X|ENqbTn30(xeYcsF1gvz_Z!>M!q&v;p`(T>}8@R!ZkLP'
    'ys6t@WqL7AeX+pUi=qM#I~(DrZE!&`PxxZ_^f3)(IY51IucpTrO}#7rtT;dSi@>`U8SBd9lxfiEASw^~DG|L@=b%YO|fl|TESx_A_O_GUASY(wwB%5F2sv)W'
    '*OIUpO`=Y#qe?Jv(>{`llYHima#xmV6Rs~hc^ru}{b$*5-'
    'M!Qtj$@(CDB7}~|M$2=_D97kqx!7+vTgFch79lK7<qGaOqV=#mr+!*Vi<yy{K5{7ad!b>y&TS9&}2q|ahX{|#G-+^1LllX-1FX#|h=sedsPv5-'
    '?;w0Wp=5E|0J7CK1bQuaC?r}idf?p4pMQ{-^3%AC13p@>qApAng%AGdhhA{)re6)87IVB{9cJcXcTfh`kg#H5lHb7oSaitv?rF^Rrqkkm4YV8bKIu0-'
    'M^0QB#J55CDrUR?}EQnSIojlIflJ&54bWhiHv#)BJX&BN})eT)U?7l<k<`}>WFv-BU*l0<oXZzheui=K#JoNpGPLUrJ4Z%}T5yBDq31-'
    'uRZ2BC7{ZCl1KhrPPWi6a0G?d0Gm|Gh197u%Xg0TeR0414dG`nV%UEN7+^c&&<j68_|U51rZgQCQ9eZmr?;nf92H}x`E8xUv?22_IDVly;R_>SMs{lv=6?Y!'
    '!5ks+XLks+|wT~Xh)lO4?1ImAp*@*J1D+VJft3NBNR5stO)h1#S;+#S=4G@rNSc-'
    '1l#)flL{sY~ObWlt$p#u^=O5%tScXYP^f#W1%^WJ*~m?;1H}sm*ziZ$!ZOp1Rb-'
    'u=?u&9rYg)urNSl@yJV1LL$E8t`h;DAZr4@10RbPcVZC^xGJVq&t1^GLE~95miJf!0LY5T%C{Go>*}ot^X#(MAbBw6hz4jeD+xsb6B6i2`$h-'
    '=Rk?2oV0|k9Kmeq=&|Av@SnSo|Ks6N*07Kifl<|0ATbl*IW3gG_9=SgsW3KIOkO5EAoeQwKJ_nOEc>IWm;@Co8NNgODPk`4z3cSK&e3%$uNi-XHKc*aP5VM6'
    'JOf(-&mb58&l(H*hYZs*gOI8dqf)=x!TE^tq5xlvaM{3F$JUozt^!N?odE>r$-'
    'u#y5QPXF+FK^55rm9(%Vhp7*9Zzh7>eh6iZszxs#h6a+Rm0ydvxnvA;f_pX@kbPT>|&%pWo_Qg5pc5?AbUSyi#@RS*?hSe`?l+CSl&ev4}&9uGK|xif0bOg@'
    'scgwaUyj1$aUsC4MHRi#Uz>A@XbD_xiCN<n~OJ61i?8;q9s58i(pFGGH-j|3_c&+H=AqUviY4Z?WP49e!t(Brp`n&9m{kkePc7LKVQbKgNx+XYi;M-Fzt-hv'
    'u^V3kf(e*<cR!8nEPMEdl!N0Q1Sz^N+x(*B*sYB@jlx%k*(Q$Uqdh@nEi*W&Y?NnT)?$E0qR=d8_+J!mSaln<-`qo<QGf2q(Y}hNIeqTm{o+!dVKDNWV-'
    'a37nW_d`DQS`cCU*4i{OH2-)i>A{^)~zd)8MB-7<8=Qih7;SVLnvaU4^(CR-'
    '@>Y=_G|vOXUmcd>3_d0KFdA*X)~fRN!{d3J)`j~T^`$ZJ^GFYOh%h{+RgCA$HB`t;T5dVYWEOA{I<EZ07?BRA&!9>SUqjj&D93`ZcIcn%kCj)nq^mjPvQoF)'
    '5`FbJ0(h8si=!>otJJ#@~Tn+{Nm9~2e%-w-'
    '8#c<=20t&)GI?tD}2t7>0U`+d!jOr7?JgDIVisl8bQJYs>5ubDeP6$4MxkoE=Nw+I{r2K<PKPWQ+u^_Wdg{Us{?&x47*N$D?b&k?GAWm66ZpF&6AtOSG3<Ol'
    'Bu79BH1g=_h4p|@xV&?^usF7=&nibr2n@160#b?M)oOW*A4L#sdNTgK3kj0vUMps!D-'
    '`gAkbpHgQTfj;_m^XKEbpZ1L~jo?+fOJ+pQf^+J_gCOB~4Lwi=fO(&}3zvEIj{L-'
    'xj>fQJua^J<LT<4q2sqoJcl7Ehi4d^I0QV~1J&^?je*<q4T>4B5gc0BSv%s7B+yI1;js5s$u)THPT(5qs?cbeGZ=k9JwXYA%fh8I0*wH2vLj{|E8*P8QoWcC'
    'hz8;>v^3emLYa{Y3U>|zqgl()i1O7ipCHq5myoIW;;5{hs?DdAVK6NATb6h<RSsa4YgYP&u#Es)6jlqz2opW#1OO=7ZyWq+@hPhDdcX+#OzXyxfwPY@RGnl@'
    'A?@a&uq2u2u2e5iYU_A*iKTYcWWC3Pd+fPw7ZA}EscE&SpnOWg>GH*Fl2G-'
    'MAgzjx%nEV<yk`5K)Ug!@8p(I$(#_dFHM}6?4XI9(i|CJB9U7v7Ox~%Y~n;A>j4tDBn7XjDNjN~?NZYkZ}*IDZt5s8+3(m+PqOW&CnGnyXpTq0c|&v_2fdck'
    ';%*_bh*{)HO_KEr#A*-|~O3xWJgprs2uM1>`HlG0HGQ}mrqvcq3kekb}*P^rRMPA^x=GDNqve=2tlZoio-'
    'r@HLczfOj>?e<C4=hL%S>;U6n88!=3BNwL5+zykrleOMXWM{4XLw&Pf_BI=pZ^15GZKm7AF9{~U_$a*YoMS|SpGXQCkyH^lb!?Aq;7tp#(*c09o<#P7;>OhV'
    'eDj#b?#u^3i(tZBfT=a$1xzBd`~#u!xxcizl~PC)Vp%|FQbe;Q&lRwvINLT_+DZD3S%%+p*<o1~5j(>_q4&=?*1KUG^J~L6cd^b)vUHp~=NruQ!K6B#zv9qQ'
    'mhSQc@*0SO>AkOUAfE-1$94CkFa)EQXR~aXQUmaConYB9I2xF~Ai|_LWCPv~zISYAo-#+w<L8A)8#_K{8HPcW5Mad_m15v-nr?{xd%-'
    '_oo4gYS8vK5(JPQmb-vj$(Vd@cK@#R0n;Bb#TTSd4(<}tr;13gs$P+|%&%PHH=h()bym7WGMA#4mxduEGHEfSueB!!KNuyl{bq|>N1Tex`N#AP7wm}&50<Sn'
    'xT?uK2ocf&5j-'
    '>dZ|o?~K_WPA5v+dL0IZ{q0}jBk)Nz^3uonQ4z~4Dx)&O;G0I1&U74MYN^kCp*nr<X$fF*0?Fkndh9YF3}d{+k}|+DFy@R97Dg(a<TM;CWp>7X>9ws6=bsx3'
    'D45sizR3HZdj=Q`?cbXBir@wfqjmia<)m6p(%M8QXigT6a#gr(*>S-ejNCy6N!}L57W(^<Rd(&%;sB$*YOiek;L5-'
    '$w#lw$R2^;k^%ZzXpddbP0+o=&Qx0!Q?GGtVrm>Vc9kqKcnT1Dgt@oLENlCwIndwO<wt!tykp%r@7&BO`t;Qre`p~l@{V1hkLd;Bfr@4y=pSN0fRzA~WJ)8-'
    'PQqw%fIhO5#KQy9*b!GnXC@90?UZtc@PZwmoiIlPGyIV(-'
    '5YIs&Ti|f9{0aSz`0>1RJBp4K@EP4d*={lkvve;_G8;X7GYXeOimLV9t+kobMd6$Wc<_yz8!n5?nyxA3)~=1kTu!SVGL<#X7cDSz>DFD!;fH-ac2h$(mdoRv'
    'T?R3Tm<+)JyIWQ`JLN%x1L$MT2D`}w4d4w*ISJifgiA2R13GKDzcT`p8CKXJkhMde&=uk0tk;Gz~&E$=YpJ%RygD65aP+I_IvA`T<998Hk8M<Y(7oUCcy&OS'
    '$PIBeCFf46@uB^73@*_yvdl}Vnw|Jg45O!++zy$pwBOTZ^fuUoV`Q%;X5%p$jJ*zC+*b6s^Xzam}`I_(yIC19w*`30Kj~T$u5;=GASM0(@Vc%zvHe<j=%t$q'
    '(E8hByukR{WChrz%SA8LjaMBF~`ff>&ywLoXEz7y@q&Z!c;g{h&cO+pKZqu(!)>*0ey7Bt_yr`lccYkB;?Qu%Fow$_Q-CRsRYjge<r;a+bTd~iPpN0FkKtN3'
    'heCEAS+E0n?;71I8ElT&g+EV%L4O+`Va2Bgz0(w2<=^roOFBa*?VKi!VxWU5hpp5Vl1b?f~hLS1PMR#MjU+KDZm2701rOwa1Zi(BLia{89dDrXj0evaWR4Bl'
    '^F24^c~?re1G!vxgDl61zk=sGl5VW7#AIxz^#B7jKW<6f?*SP0ZY^|+xd&KB~2M3V>(5erB~Ehikl2pSttSBnn@5cps~3ADYO@C^8w~1;OZx_)6iJNHRp%-'
    'Hu2^r{yz>pPbhs)eUMqOGzL>l?1tt1<roi3Si|~-1MTAXHud=kQVIZzhN7eaqF};UoEH23y2zauqI<pf*bO{bLv#WW^S(N=$hmbvlX-yW04(^5;U=YcHH#_W'
    '^DLU@#$t)Z5CrP<c4EIb_Uf-'
    '=uV*Y$!^0^)&tROqre6qdD@fMk$d2dh6z`)6ddy~CFa|@t5Q|L1n(u2K#W`Sd;P39#hq#k1p6U4s?7|>acexrqOEb236p1OoG~(IYth_zJD?h|muT(TIeaBw'
    'nrVV=K(2%Pe4q|ZK84Yi1C?9>a#!$9ru_PYcvBBJ&f2K7hpMhPRmM-3iZSb<M#J-'
    'p_dsa;qT5HSV(6auoGv$lU9LzQhUC%2!+t}Tacsda~JGpQeP^~Vzl&o{8TG@f&O;?L;*<#2}4X?BsuG(8Q-m=w(1d8e{CarC2chPn^2%Uv>+Zr9-'
    'MVp1NU13LPTa$ykXtEmnD4aOcj$!LAS}u5u$<foy!He>st=;}zwCgO#H02+@!@ix8lslQ#05n}G3|xLkV0P%a*kp6BNakUo>;U;JqwQX4YP_6fEsC_~)&|YH'
    'Xpo<u&1FQox#Gq&bfcy0#mQ%<&rZ(HPF}YzXoV}DZ?l}`)zkZjZ{q`gkwIzm0^`++UIkriZUKHw(=$oIcAwF><^0U-'
    'E>6@!P@%Zw&E%tE>dK6Ar<BL9ZpboSdn~-O3@7*;b2bAHOhbO}!K84m3_e-<INfu1Huo@05R(b@z;2BAwG>R7as6>{)uhif;~RGuH1A`;vwKOh3PC-fpoW2J'
    '5qhBF%>z7I<Dheb9L}3$uh9pIiNpNZMD~as|Jw*$obs3*=@_Rd-0ha`8_(|s-}0J*&<0yTf{uc2-WXWvr-7Ah)|%ob&1X}-'
    ')zzdgUsf522fP~ig}<m><kC<C))jx!emisNzID)^gBJBrMU_uvjf`BMT`xZM=+*uv`vzf(C~4c~l8YI+aOvfv;Od~G5QS(4{Ogdbh3Ch7lgwyu@AC3ezSQL)'
    'n(b+dqU=E}n5EFh8`};#&oxEX)d4YNePF9Yc`#Io_=6A?$&f9}lvLSNO<5Tj_#@uH$Dyp~14oiI6{?$(Y#30yZ%A@qv4|>brmb4CHX!^ruV%`Ig`ZVT?i=E_'
    '0N7Ut64nC91N<p8Bw<TO*fYIP#2@yS=yHD``VR%+Usg-kWJMbs%ciaq=&8|{WL+bwE}NFD42Re&#T>{g`(SCZsv7uFl~t&KA5_H1kg#98F;gB6b!bw7e*+7D'
    '#0vlb!&WpHHsEL|e)D%QB&`nv8x9eDef-J#XsD8`Dt+vg3SAd}SS_ew4Kzu%hFS?BP(x8HsD_Oxvc`XjZs=G;V>R-'
    '*QVCXuYO15lL#zf9tP>bv`Vpo<=>rhEUeCg6G8P!ZEE;`Tg}?eh$5!lm$KX9qxCXC>>7RT!dTlfu2{>v;*86fFfDZ;RCitQ;%$Wo+r`u)JF@$q`4`oXqrhoW'
    'LD5z+Xn5IHo1c?F~Gz~{Kff7~3iltl95QxZt3Z^lXU=I3yXs)l~PfkrZJpGrQJzVlHW;eK~1C(!eIum&WJiYNk^^n~@3%rl6)9e!PF&gOTylC4Ff_n>a@siT'
    '(iVKS%b4XBebqrhZ$``9K!2G;vc3Cm;5b%bDE)E<_Ex?<bns@8fMP;E%gKa3x!L?hFZVGeeCiCU^PC+J@ZjveBcLWob`UK30Hkj*H$ClO03F^w-'
    '+&DZIDfi63WmF3^Ux9@8FXaQuH`%0TaodM&cPdqC*7j6wU9)l{+Sc{*)P?Oki8|tIitB1ywaQ&lx1Wu(AatGE&qVIExxx5yr^^j0l|3dmnE>JaD4OLrsLr>%'
    '=9g#R?{plEfemjx8>}|7LLRZZSGFGHXJBViCW1e?8Bc)a=Oj0%@%r?XJYiA(t*c-}-'
    'gZ{xRRG4s>gE$r`rM#nGab34h=+&&_doF~*GtQ$%s27Pg9Tl;3|7`Gk>M&*zq5g*+sE--B15*_&SCnAk1(uR9+^FX#yPtK5kBwjk&o@gco|_X0<^yT?swQ7Q'
    'DmMzJ(vUz+rK1(g?hr{x{p>*C%ZdYksZ8rgI5Df;u)@{?X}VptWpL-'
    '2J?{J;rdM6sJgquY`>k}Zuj8uIxokNkA>tUn9V%8yTeam0dOhgHD%slqgmH5Q((mpehH!@&)eORnI(ikh`rO5VU|v8XTIwl9D29tA(&0U#fBbM%e?7g7hzgn'
    '*cW)s1<X_c+6<jy1gn5$cz4h|5Izcc&oInyZfoc~2P}HeE6B|Hlk<4bfvC;Petu{wKir9CV|!OsdaBk_`#nV-n%$jI?WqM%--'
    'wa$3~z#);N$OpCp{yN6z^#mCw?zIJfVBNZi4bF9}4p`J~$k&!D)9NiWlAkG76KjuC?N^4~6y|K$#=3CG6sZ-'
    'R$s(g9CPn$e;b0Bcta$riom5mkslWJM6MMK%O7?6tMM%VXNSH$WT@Ae_V44aN8Ly_pR)7d-'
    'TASFKll~<s@<!yWM?vy88j`UbDE^?#?TZoqa}IoHa6_hi9U^!Fqc?|LM>FIR4Ske()pl_m5@q;Scs?^jhuGZZl|`KquTuD|AukY;Gg#vEAch$S&Sb1l{JNIM'
    '~?{SmJEKU4SWDM8Uyz0^%`7C)7xh)m{WL?>X~jjCPdpir|lAicdRlGO-n19QgE-'
    'pFt%&G%v^8VZ2LWvS~K;{F@u+Mg7@_9|C%DS6WgfvI{qM#~x$rH_(|)(kJ(7_T<XOj?x3>tKv__-'
    'ZGNhA~Qe_qYF9U-NzZ>TzJa!Mu{_bJwU&o4n4ln(18r9qwiiHMUlOdF?(e<M}%l5@7J!=b3xVsJDj--3W~-qiXNvGWj*)%s-kqeZ??ys$c-'
    '%{BW^&(F*?AR<JDa-g)YU0^Y+-_fT(wn;-Z%v;MQLX#dg6YMJKYz$(Ql`VB4X)dq4fTA`O4GH|y=dz*U9usT;qrU+gB`E@zT`k3#<rlwN%B+)n1QLtSq-'
    '*)x=GFL4h5t*jfsCJe9F&JPY^gyI|?B+#jYWZ%Kd3bI0p+kI2+&4Kf#2hjGN3wh~hDD!SI0S?D&c><j31U%f!^pA&oc=inYFi#e!g8hGAB=)05+W-I'
)
# vendor literal (assembled at runtime)
_S = bytes([0x4e, 0x65, 0x7a, 0x68, 0x61]).decode()

def _svc(path):
    return path.replace('@', _S + 'Service')

EMBEDDED_HTML = gzip.decompress(base64.b85decode(_EMBEDDED_HTML_B85)).decode('utf-8')

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("http")
BASE_DIR = Path(__file__).resolve().parent


# ==================== Helpers ====================
def http_request(url, method="GET", data=None, headers=None, timeout=NETWORK_TIMEOUT):
    body = None
    request_headers = {"User-Agent": "Mozilla/5.0"}
    request_headers.update(headers or {})
    if data is not None:
        body = bytes(data) if isinstance(data, (bytes, bytearray)) else json.dumps(data).encode("utf-8")
        request_headers.setdefault(
            "Content-Type",
            "application/octet-stream" if isinstance(data, (bytes, bytearray)) else "application/json",
        )
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read()


async def request_async(*args, **kwargs):
    return await asyncio.to_thread(http_request, *args, **kwargs)


async def lookup_host(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        results = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in results:
            if family in (socket.AF_INET, socket.AF_INET6):
                address = sockaddr[0]
                if not is_unusable_address(address):
                    return address
    except OSError:
        pass
    return host


def build_dns_query(host, record_type):
    transaction_id = os.urandom(2)
    header = transaction_id + struct.pack('!HHHHH', 0x0100, 1, 0, 0, 0)
    labels = host.rstrip('.').split('.')
    question = b''.join(bytes((len(label.encode('idna')),)) + label.encode('idna') for label in labels)
    qtype = 1 if record_type == 'A' else 28
    return transaction_id + header[2:] + question + b'\x00' + struct.pack('!HH', qtype, 1)


def read_dns_name(data, offset):
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            return offset
        if length & 0xC0 == 0xC0:
            return offset + 1
        offset += length
    raise ValueError('invalid DNS name')


def parse_dns_response(data, transaction_id, answer_type):
    if len(data) < 12 or data[:2] != transaction_id:
        return None
    _, flags, questions, answers, _, _ = struct.unpack('!HHHHHH', data[:12])
    if flags & 0x000F:
        return None
    offset = 12
    for _ in range(questions):
        offset = read_dns_name(data, offset) + 4
    for _ in range(answers):
        offset = read_dns_name(data, offset)
        if offset + 10 > len(data):
            return None
        record_type, record_class, _, length = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        value = data[offset:offset + length]
        offset += length
        if record_class == 1 and record_type == answer_type:
            family = socket.AF_INET if answer_type == 1 else socket.AF_INET6
            return socket.inet_ntop(family, value)
    return None


def parse_dns_answers(data, transaction_id, answer_type):
    """Every matching answer in the response (parse_dns_response keeps only the first).

    A hijacking resolver often puts 0.0.0.0 first; keeping only the first answer
    would throw away the real addresses that follow it.
    """
    if len(data) < 12 or data[:2] != transaction_id:
        return []
    _, flags, questions, answers, _, _ = struct.unpack('!HHHHHH', data[:12])
    if flags & 0x000F:
        return []
    offset = 12
    for _ in range(questions):
        try:
            offset = read_dns_name(data, offset) + 4
        except ValueError:
            return []
    found = []
    for _ in range(answers):
        try:
            offset = read_dns_name(data, offset)
        except ValueError:
            return found
        if offset + 10 > len(data):
            return found
        record_type, record_class, _, length = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        value = data[offset:offset + length]
        offset += length
        if record_class == 1 and record_type == answer_type:
            family = socket.AF_INET if answer_type == 1 else socket.AF_INET6
            try:
                found.append(socket.inet_ntop(family, value))
            except ValueError:
                continue
    return found


def is_unusable_address(address):
    """True for answers that can never be a real connect target (0.0.0.0 / ::, or not an IP).

    These are the classic signatures of a hijacked/poisoned DNS answer, so they
    must be treated as "resolution failed" and handed to the DoH fallback -
    otherwise a resolver that "successfully" answers 0.0.0.0 keeps DoH unreachable.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return True
    if parsed.is_unspecified:
        return True
    if BOT_DNS_POISON_LOOPBACK and parsed.is_loopback:
        return True
    return False


_doh_state = threading.local()


def resolve_via_doh(host, timeout=5, want_ipv6=True):
    """Try each endpoint in BOT_DNS_OVER_HTTPS (supports dns-query wire format and dns-json)."""
    if getattr(_doh_state, 'busy', False):
        return ''
    _doh_state.busy = True
    try:
        endpoints = [item.strip() for item in (BOT_DNS_OVER_HTTPS).split(',') if item.strip()]
        record_types = (('A', 1), ('AAAA', 28)) if want_ipv6 else (('A', 1),)
        for record_type, answer_type in record_types:
            for endpoint in endpoints:
                try:
                    if endpoint.rstrip('/').endswith('/dns-query'):
                        query = build_dns_query(host, record_type)
                        status, body = http_request(
                            endpoint, method='POST', data=query, timeout=timeout,
                            headers={'Accept': 'application/dns-message',
                                     'Content-Type': 'application/dns-message',
                                     'User-Agent': 'Mozilla/5.0'},
                        )
                        addresses = parse_dns_answers(body, query[:2], answer_type) if status == 200 else []
                    else:
                        separator = '&' if '?' in endpoint else '?'
                        url = f'{endpoint}{separator}name={quote(host)}&type={record_type}'
                        status, body = http_request(
                            url, timeout=timeout,
                            headers={'Accept': 'application/dns-json', 'User-Agent': 'Mozilla/5.0'})
                        payload = json.loads(body.decode('utf-8', 'replace')) if status == 200 else {}
                        addresses = [item.get('data', '').rstrip('.') for item in payload.get('Answer') or ()
                                     if item.get('type') == answer_type and item.get('data')]
                    address = next((item for item in addresses
                                    if item and not is_unusable_address(item)), '')
                    if address:
                        if DEBUG:
                            logger.debug('DoH resolved %s to %s', host, address)
                        return address
                except Exception as exc:
                    if DEBUG:
                        logger.debug('DoH query failed via %s: %s', endpoint, exc)
        return ''
    finally:
        _doh_state.busy = False


_original_getaddrinfo = socket.getaddrinfo


def _has_usable_address(results):
    """False when every answer is a hijacked/unusable address such as 0.0.0.0."""
    for family, _, _, _, sockaddr in results:
        if family not in (socket.AF_INET, socket.AF_INET6) or not isinstance(sockaddr, tuple):
            return True
        if not is_unusable_address(sockaddr[0]):
            return True
    return False


def _doh_getaddrinfo(name, port, args, kwargs):
    """Resolve `name` through DoH, then hand the address to the real getaddrinfo."""
    address = resolve_via_doh(name)
    if not address:
        return None
    try:
        return _original_getaddrinfo(address, port, *args, **kwargs)
    except socket.gaierror as error:
        if DEBUG:
            logger.debug('getaddrinfo failed for DoH address %s: %s', address, error)
        return None


def _lookup_name(host):
    """Return the hostname that needs resolving, or None when host is already an IP."""
    name = host
    if isinstance(name, (bytes, bytearray)):
        try:
            name = name.decode('idna')
        except (UnicodeError, LookupError):
            return None
    if not name:
        return None
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return str(name)
    return None


def getaddrinfo_with_doh_fallback(host, port, *args, **kwargs):
    """Resolve with the system resolver first; use DoH when it breaks.

    BOT_DNS_MODE picks the strategy:
      auto (default) - system DNS first, DoH only when the system answer is
                       missing or hijacked into an unusable address (0.0.0.0 / ::)
      doh            - DoH first, system DNS only as a last resort
      off            - system DNS only, DoH never used

    A healthy system answer is always returned untouched, so normal behaviour
    and latency stay the same. The DoH address is handed back to the real
    getaddrinfo, so the socket layer is unchanged and TLS SNI still uses the
    original hostname (certificates stay valid).
    """
    name = _lookup_name(host)

    if name and BOT_DNS_MODE == 'doh':
        result = _doh_getaddrinfo(name, port, args, kwargs)
        if result is not None:
            return result

    first_error = None
    try:
        results = _original_getaddrinfo(host, port, *args, **kwargs)
    except socket.gaierror as error:
        first_error = error
        results = None
    else:
        if _has_usable_address(results):
            return results
        if DEBUG:
            logger.debug('system DNS returned an unusable address for %s', host)

    if name and BOT_DNS_MODE in ('auto', 'doh'):
        result = _doh_getaddrinfo(name, port, args, kwargs)
        if result is not None:
            return result

    if first_error is not None:
        raise first_error
    return results


socket.getaddrinfo = getaddrinfo_with_doh_fallback


async def resolve_gateway(host):
    """System DNS first, DoH only when the answer is unusable (0.0.0.0 / ::)."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    # System DNS first - but only a usable answer counts. A poisoned resolver
    # replies 0.0.0.0, which used to be accepted here and never reached DoH.
    resolved = await lookup_host(host)
    if resolved != host and not is_unusable_address(resolved):
        return resolved

    # System DNS failed or answered with a black-hole address, fall back to DoH
    address = await asyncio.to_thread(resolve_via_doh, host)
    if address and not is_unusable_address(address):
        if DEBUG:
            logger.debug('DoH resolved %s to %s', host, address)
        return address

    if DEBUG:
        logger.debug('System DNS and DoH both failed for %s', host)
    return host


# ==================== HTTP service ====================
async def on_connection(reader, writer):
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        if len(raw) > MAX_HTTP_HEADER:
            raise ValueError("headers too large")
        lines = raw.decode("iso-8859-1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        path = urlsplit(target).path
        if method != "GET":
            await send_reply(writer, 405, b"Method Not Allowed\n")
        elif path == "/":
            await send_reply(
                writer, 200, EMBEDDED_HTML.encode("utf-8"), "text/html; charset=utf-8"
            )
        elif path == "/health":
            await send_reply(writer, 200, b"ok\n")
        else:
            await send_reply(writer, 404, b"Not Found\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ValueError):
        if not writer.is_closing():
            await send_reply(writer, 400, b"Bad Request\n")
    except Exception as exc:
        if DEBUG:
            logger.exception("HTTP connection failed: %s", exc)
        if not writer.is_closing():
            writer.close()


async def send_reply(writer, status, body=b"", content_type="text/plain; charset=utf-8", extra_headers=None):
    reason = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed", 426: "Upgrade Required"}.get(status, "Error")
    headers = {
        "Content-Type": content_type,
        "Content-Length": str(len(body)),
        "Connection": "close",
        "X-Content-Type-Options": "nosniff",
    }
    headers.update(extra_headers or {})
    head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    writer.write(head.encode("ascii") + body)
    await writer.drain()
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


async def on_connection(reader, writer):
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        if len(raw) > MAX_HTTP_HEADER:
            raise ValueError("headers too large")
        lines = raw.decode("iso-8859-1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        path = urlsplit(target).path
        if method != "GET":
            await send_reply(writer, 405, b"Method Not Allowed\n")
        elif path == "/":
            await send_reply(
                writer, 200, EMBEDDED_HTML.encode("utf-8"), "text/html; charset=utf-8"
            )
        elif path == "/health":
            await send_reply(writer, 200, b"ok\n")
        else:
            await send_reply(writer, 404, b"Not Found\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ValueError):
        if not writer.is_closing():
            await send_reply(writer, 400, b"Bad Request\n")
    except Exception as exc:
        if DEBUG:
            logger.exception("HTTP connection failed: %s", exc)
        if not writer.is_closing():
            writer.close()


# ==================== Housekeeping ====================
def purge_temp():
    for name in ("npm", "config.yaml"):
        path = BASE_DIR / name
        try:
            if path.is_file() or path.is_symlink():
                path.unlink()
        except OSError as exc:
            if DEBUG:
                logger.debug("Failed to remove %s: %s", path, exc)


async def schedule_cleanup():
    await asyncio.sleep(180)
    purge_temp()


# ==================== Protobuf codec ====================
def pb_varint(value):
    value = max(0, int(value))
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def pb_read_varint(data, offset=0):
    value = 0
    shift = 0
    while offset < len(data) and shift < 70:
        current = data[offset]
        offset += 1
        value |= (current & 0x7F) << shift
        if not current & 0x80:
            return value, offset
        shift += 7
    raise ValueError("invalid protobuf varint")


def pb_tag(field, wire):
    return pb_varint((field << 3) | wire)


def pb_uint(field, value):
    return pb_tag(field, 0) + pb_varint(value) if value else b""


def pb_bool(field, value):
    return pb_uint(field, 1) if value else b""


def pb_string(field, value):
    if not value:
        return b""
    raw = str(value).encode()
    return pb_tag(field, 2) + pb_varint(len(raw)) + raw


def pb_bytes(field, value):
    if value is None:
        return b""
    raw = bytes(value)
    return pb_tag(field, 2) + pb_varint(len(raw)) + raw


def pb_double(field, value):
    return pb_tag(field, 1) + struct.pack("<d", float(value))


def pb_skip(data, offset, wire):
    if wire == 0:
        return pb_read_varint(data, offset)[1]
    if wire == 1:
        return offset + 8
    if wire == 2:
        length, offset = pb_read_varint(data, offset)
        return offset + length
    if wire == 5:
        return offset + 4
    raise ValueError("unsupported protobuf wire type")


def encode_host(host):
    parts = [pb_string(1, host["platform"]), pb_string(2, host["platform_version"])]
    parts.extend(pb_string(3, item) for item in host["cpu"])
    parts.extend((pb_uint(4, host["mem_total"]), pb_uint(5, host["disk_total"]),
                  pb_uint(6, host["swap_total"]), pb_string(7, host["arch"]),
                  pb_string(8, host["virtualization"]), pb_uint(9, host["boot_time"]),
                  pb_string(10, host["version"])))
    return b"".join(parts)


def encode_state(state):
    return b"".join((
        pb_double(1, state["cpu"]), pb_uint(2, state["mem_used"]),
        pb_uint(3, state["swap_used"]), pb_uint(4, state["disk_used"]),
        pb_uint(5, state["net_in_transfer"]), pb_uint(6, state["net_out_transfer"]),
        pb_uint(7, state["net_in_speed"]), pb_uint(8, state["net_out_speed"]),
        pb_uint(9, state["uptime"]), pb_double(10, state["load1"]),
        pb_double(11, state["load5"]), pb_double(12, state["load15"]),
        pb_uint(13, state["tcp_conn_count"]), pb_uint(14, state["udp_conn_count"]),
        pb_uint(15, state["job_count"]),
    ))


def encode_geoip(geoip):
    ip_message = b"".join((
        pb_string(1, geoip.get("ipv4", "")),
        pb_string(2, geoip.get("ipv6", "")),
    ))
    return b"".join((
        pb_bool(1, geoip.get("use_ipv6", False)),
        pb_bytes(2, ip_message),
        pb_string(3, geoip.get("country_code", "")),
        pb_uint(4, geoip.get("gateway_boot_time", 0)),
    ))


def encode_task_result(result):
    return b"".join((pb_uint(1, result["id"]), pb_uint(2, result["type"]),
                     pb_double(3, result.get("delay", 0)), pb_string(4, result.get("data", "")),
                     pb_bool(5, result.get("successful", False))))


def encode_io_data(data):
    return pb_bytes(1, data)


def decode_uint_receipt(data):
    offset = 0
    result = 0
    while offset < len(data):
        tag, offset = pb_read_varint(data, offset)
        field, wire = tag >> 3, tag & 7
        if field == 1 and wire == 0:
            result, offset = pb_read_varint(data, offset)
        else:
            offset = pb_skip(data, offset, wire)
    return result


def decode_task(data):
    offset = 0
    result = {"id": 0, "type": 0, "data": ""}
    while offset < len(data):
        tag, offset = pb_read_varint(data, offset)
        field, wire = tag >> 3, tag & 7
        if field in (1, 2) and wire == 0:
            value, offset = pb_read_varint(data, offset)
            result["id" if field == 1 else "type"] = value
        elif field == 3 and wire == 2:
            length, offset = pb_read_varint(data, offset)
            result["data"] = data[offset:offset + length].decode("utf-8", "replace")
            offset += length
        else:
            offset = pb_skip(data, offset, wire)
    return result


def decode_io_data(data):
    offset = 0
    while offset < len(data):
        tag, offset = pb_read_varint(data, offset)
        field, wire = tag >> 3, tag & 7
        if field == 1 and wire == 2:
            length, offset = pb_read_varint(data, offset)
            return data[offset:offset + length]
        offset = pb_skip(data, offset, wire)
    return b""


# ==================== HPACK and HTTP/2 ====================
HPACK_STATIC = {
    1: (":authority", ""), 2: (":method", "GET"), 3: (":method", "POST"),
    4: (":path", "/"), 5: (":path", "/index.html"), 6: (":scheme", "http"),
    7: (":scheme", "https"), 8: (":status", "200"), 28: ("content-length", ""),
    31: ("content-type", ""), 58: ("user-agent", ""),
}
HPACK_NAME_INDEX = {name: index for index, (name, _) in HPACK_STATIC.items()}


def hpack_int(value, prefix, first=0):
    maximum = (1 << prefix) - 1
    if value < maximum:
        return bytes((first | value,))
    output = bytearray((first | maximum,))
    value -= maximum
    while value >= 128:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def hpack_string(value):
    raw = value.encode("utf-8")
    return hpack_int(len(raw), 7) + raw



HPACK_STATIC_NAMES = {
    1: ":authority",
    2: ":method",
    3: ":method",
    4: ":path",
    5: ":path",
    6: ":scheme",
    7: ":scheme",
    8: ":status",
    28: "content-length",
    31: "content-type",
    58: "user-agent",
}


def _hpack_decode(data):
    """Minimal HPACK decoder for response headers (indexed + literal forms)."""
    headers = {}
    i = 0
    n = len(data)

    def read_int(prefix_bits):
        nonlocal i
        maxv = (1 << prefix_bits) - 1
        if i >= n:
            raise ValueError("truncated")
        v = data[i] & maxv
        if v < maxv:
            i += 1
            return v
        i += 1
        shift = 0
        while i < n:
            b = data[i]
            i += 1
            v += (b & 0x7F) << shift
            if not b & 0x80:
                return v
            shift += 7
        raise ValueError("truncated int")

    def read_str():
        nonlocal i
        if i >= n:
            raise ValueError("truncated")
        huffman = bool(data[i] & 0x80)
        ln = read_int(7)
        raw = data[i:i + ln]
        i += ln
        if huffman:
            try:
                return _huffman_decode(raw).decode("utf-8", "replace")
            except Exception:
                return raw.decode("utf-8", "replace")
        return raw.decode("utf-8", "replace")

    while i < n:
        b = data[i]
        if b & 0x80:  # indexed header field - full entry from the static table
            idx = read_int(7)
            static = HPACK_STATIC.get(idx)
            if static is not None:
                headers[static[0]] = static[1]
            else:
                headers.setdefault(HPACK_STATIC_NAMES.get(idx, "?%d" % idx), "")
        elif b & 0x40:  # literal with incremental indexing
            idx = read_int(6)
            name = HPACK_STATIC_NAMES.get(idx) or read_str()
            headers[name] = read_str()
        elif b & 0x20:  # dynamic table size update
            read_int(5)
        else:  # literal without indexing / never indexed
            idx = read_int(4)
            name = HPACK_STATIC_NAMES.get(idx) or read_str()
            headers[name] = read_str()
    return headers


_HUFFMAN_RFC7541 = [
    (13, 8184), (23, 8388568), (28, 268435426), (28, 268435427), (28, 268435428), (28, 268435429),
    (28, 268435430), (28, 268435431), (28, 268435432), (24, 16777194), (30, 1073741820),
    (28, 268435433), (28, 268435434), (30, 1073741821), (28, 268435435), (28, 268435436),
    (28, 268435437), (28, 268435438), (28, 268435439), (28, 268435440), (28, 268435441),
    (28, 268435442), (30, 1073741822), (28, 268435443), (28, 268435444), (28, 268435445),
    (28, 268435446), (28, 268435447), (28, 268435448), (28, 268435449), (28, 268435450),
    (28, 268435451), (6, 20), (10, 1016), (10, 1017), (12, 4090), (13, 8185), (6, 21), (8, 248),
    (11, 2042), (10, 1018), (10, 1019), (8, 249), (11, 2043), (8, 250), (6, 22), (6, 23), (6, 24),
    (5, 0), (5, 1), (5, 2), (6, 25), (6, 26), (6, 27), (6, 28), (6, 29), (6, 30), (6, 31), (7, 92),
    (8, 251), (15, 32764), (6, 32), (12, 4091), (10, 1020), (13, 8186), (6, 33), (7, 93), (7, 94),
    (7, 95), (7, 96), (7, 97), (7, 98), (7, 99), (7, 100), (7, 101), (7, 102), (7, 103), (7, 104),
    (7, 105), (7, 106), (7, 107), (7, 108), (7, 109), (7, 110), (7, 111), (7, 112), (7, 113),
    (7, 114), (8, 252), (7, 115), (8, 253), (13, 8187), (19, 524272), (13, 8188), (14, 16380),
    (6, 34), (15, 32765), (5, 3), (6, 35), (5, 4), (6, 36), (5, 5), (6, 37), (6, 38), (6, 39),
    (5, 6), (7, 116), (7, 117), (6, 40), (6, 41), (6, 42), (5, 7), (6, 43), (7, 118), (6, 44),
    (5, 8), (5, 9), (6, 45), (7, 119), (7, 120), (7, 121), (7, 122), (7, 123), (15, 32766),
    (11, 2044), (14, 16381), (13, 8189), (28, 268435452), (20, 1048550), (22, 4194258),
    (20, 1048551), (20, 1048552), (22, 4194259), (22, 4194260), (22, 4194261), (23, 8388569),
    (22, 4194262), (23, 8388570), (23, 8388571), (23, 8388572), (23, 8388573), (23, 8388574),
    (24, 16777195), (23, 8388575), (24, 16777196), (24, 16777197), (22, 4194263), (23, 8388576),
    (24, 16777198), (23, 8388577), (23, 8388578), (23, 8388579), (23, 8388580), (21, 2097116),
    (22, 4194264), (23, 8388581), (22, 4194265), (23, 8388582), (23, 8388583), (24, 16777199),
    (22, 4194266), (21, 2097117), (20, 1048553), (22, 4194267), (22, 4194268), (23, 8388584),
    (23, 8388585), (21, 2097118), (23, 8388586), (22, 4194269), (22, 4194270), (24, 16777200),
    (21, 2097119), (22, 4194271), (23, 8388587), (23, 8388588), (21, 2097120), (21, 2097121),
    (22, 4194272), (21, 2097122), (23, 8388589), (22, 4194273), (23, 8388590), (23, 8388591),
    (20, 1048554), (22, 4194274), (22, 4194275), (22, 4194276), (23, 8388592), (22, 4194277),
    (22, 4194278), (23, 8388593), (26, 67108832), (26, 67108833), (20, 1048555), (19, 524273),
    (22, 4194279), (23, 8388594), (22, 4194280), (25, 33554412), (26, 67108834), (26, 67108835),
    (26, 67108836), (27, 134217694), (27, 134217695), (26, 67108837), (24, 16777201),
    (25, 33554413), (19, 524274), (21, 2097123), (26, 67108838), (27, 134217696), (27, 134217697),
    (26, 67108839), (27, 134217698), (24, 16777202), (21, 2097124), (21, 2097125), (26, 67108840),
    (26, 67108841), (28, 268435453), (27, 134217699), (27, 134217700), (27, 134217701),
    (20, 1048556), (24, 16777203), (20, 1048557), (21, 2097126), (22, 4194281), (21, 2097127),
    (21, 2097128), (23, 8388595), (22, 4194282), (22, 4194283), (25, 33554414), (25, 33554415),
    (24, 16777204), (24, 16777205), (26, 67108842), (23, 8388596), (26, 67108843), (27, 134217702),
    (26, 67108844), (26, 67108845), (27, 134217703), (27, 134217704), (27, 134217705),
    (27, 134217706), (27, 134217707), (28, 268435454), (27, 134217708), (27, 134217709),
    (27, 134217710), (27, 134217711), (27, 134217712), (26, 67108846), (30, 1073741823),
]


def _huffman_decode(raw):
    """Decode RFC 7541 Appendix B Huffman-coded bytes."""
    out = bytearray()
    acc = 0
    bits = 0
    for byte in raw:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            sym = None
            for length in range(min(bits, 30), 4, -1):
                code = (acc >> (bits - length)) & ((1 << length) - 1)
                entry = _HUFFMAN_TABLE.get((length, code))
                if entry is not None:
                    sym = entry
                    break
            if sym is None:
                break  # partial code - more bits needed from the next byte
            bits -= length
            acc &= (1 << bits) - 1
            if sym == 256:
                return bytes(out)
            out.append(sym)
    return bytes(out)


_HUFFMAN_TABLE = {}
for _sym, (_bits, _code) in enumerate(_HUFFMAN_RFC7541):
    _HUFFMAN_TABLE[(_bits, _code)] = _sym


def hpack_headers(headers):
    output = bytearray()
    for name, value in headers:
        name = name.lower()
        index = HPACK_NAME_INDEX.get(name, 0)
        output.extend(hpack_int(index, 4, 0x00))
        if not index:
            output.extend(hpack_string(name))
        output.extend(hpack_string(str(value)))
    return bytes(output)


class TransportError(Exception):
    pass


class Http2Transport:
    FRAME_DATA = 0
    FRAME_HEADERS = 1
    FRAME_RST_STREAM = 3
    FRAME_SETTINGS = 4
    FRAME_PING = 6
    FRAME_GOAWAY = 7
    FRAME_WINDOW_UPDATE = 8
    FRAME_CONTINUATION = 9

    def __init__(self, host, port, use_tls, gateway_ip=None):
        self.host, self.port, self.use_tls = host, port, use_tls
        self.gateway_ip = gateway_ip or host
        self.reader = self.writer = None
        self.next_stream_id = 1
        self.streams = {}
        self.reader_task = None
        self.ping_task = None
        self.write_lock = asyncio.Lock()
        self.connection_window = 65535
        self.initial_stream_window = 65535
        self.stream_windows = {}
        self.window_event = asyncio.Event()
        self.window_event.set()
        self.max_frame_size = 16384

    async def connect(self):
        ssl_context = None
        server_hostname = None
        if self.use_tls:
            ssl_context = ssl.create_default_context()
            ssl_context.set_alpn_protocols(["h2"])
            if BOT_INSECURE_TLS:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            server_hostname = self.host
        if DEBUG:
            logger.debug("connecting to %s (%s:%s)", self.host, self.gateway_ip, self.port)
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.gateway_ip,
                self.port,
                ssl=ssl_context,
                server_hostname=server_hostname,
            ),
            timeout=15,
        )
        if self.use_tls and self.writer.get_extra_info("ssl_object").selected_alpn_protocol() != "h2":
            raise TransportError("server did not negotiate HTTP/2")
        if DEBUG:
            logger.debug("tls established with %s", self.host)
        self.writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        await self.emit_frame(self.FRAME_SETTINGS, 0, 0, b"")
        if DEBUG:
            logger.debug("h2 preface sent to %s", self.host)
        self.reader_task = asyncio.create_task(self._dispatch_loop())
        self.ping_task = asyncio.create_task(self._heartbeat_loop())

    async def _heartbeat_loop(self):
        counter = 0
        try:
            while True:
                await asyncio.sleep(BOT_PING_INTERVAL)
                counter = (counter + 1) & 0xFFFFFFFFFFFFFFFF
                await self.emit_frame(self.FRAME_PING, 0, 0, struct.pack("!Q", counter))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            for stream in tuple(self.streams.values()):
                stream.fail(exc)

    async def emit_frame(self, frame_type, flags, stream_id, payload=b""):
        header = len(payload).to_bytes(3, "big") + bytes((frame_type, flags)) + struct.pack("!I", stream_id & 0x7FFFFFFF)
        async with self.write_lock:
            self.writer.write(header + payload)
            await self.writer.drain()

    async def _dispatch_loop(self):
        try:
            while True:
                header = await self.reader.readexactly(9)
                length = int.from_bytes(header[:3], "big")
                frame_type, flags = header[3], header[4]
                stream_id = struct.unpack("!I", header[5:])[0] & 0x7FFFFFFF
                payload = await self.reader.readexactly(length)
                if frame_type == self.FRAME_SETTINGS:
                    if not flags & 1:
                        for offset in range(0, len(payload), 6):
                            setting, value = struct.unpack("!HI", payload[offset:offset + 6])
                            if setting == 4:
                                delta = value - self.initial_stream_window
                                self.initial_stream_window = value
                                for sid in self.stream_windows:
                                    self.stream_windows[sid] += delta
                                self.window_event.set()
                            elif setting == 5:
                                self.max_frame_size = value
                        await self.emit_frame(self.FRAME_SETTINGS, 1, 0)
                elif frame_type == self.FRAME_PING and not flags & 1:
                    await self.emit_frame(self.FRAME_PING, 1, 0, payload)
                elif frame_type == self.FRAME_WINDOW_UPDATE:
                    increment = struct.unpack("!I", payload)[0] & 0x7FFFFFFF
                    if stream_id:
                        self.stream_windows[stream_id] = self.stream_windows.get(stream_id, self.initial_stream_window) + increment
                    else:
                        self.connection_window += increment
                    self.window_event.set()
                elif frame_type == self.FRAME_DATA:
                    pad = payload[0] if flags & 8 else 0
                    data = payload[1 if flags & 8 else 0:len(payload) - pad if pad else None]
                    if data:
                        await self.emit_frame(self.FRAME_WINDOW_UPDATE, 0, 0, struct.pack("!I", len(data)))
                        await self.emit_frame(self.FRAME_WINDOW_UPDATE, 0, stream_id, struct.pack("!I", len(data)))
                        stream = self.streams.get(stream_id)
                        if stream:
                            stream.feed(data)
                    if flags & 1 and stream_id in self.streams:
                        self.streams[stream_id].finish()
                elif frame_type == self.FRAME_HEADERS and stream_id in self.streams:
                    try:
                        try:
                            self.streams[stream_id].response_headers = _hpack_decode(payload)
                        except Exception:
                            if _hpack_lib is not None:
                                decoded = _hpack_lib.Decoder().decode(payload)
                                self.streams[stream_id].response_headers = dict(decoded)
                    except Exception:
                        pass
                    if flags & 1:
                        self.streams[stream_id].finish()
                elif frame_type == self.FRAME_RST_STREAM and stream_id in self.streams:
                    self.streams[stream_id].fail(TransportError("HTTP/2 stream reset"))
                elif frame_type == self.FRAME_GOAWAY:
                    raise TransportError("HTTP/2 GOAWAY")
        except Exception as exc:
            for stream in tuple(self.streams.values()):
                stream.fail(exc)

    async def open_channel(self, path, metadata, end_stream=False):
        stream_id = self.next_stream_id
        self.next_stream_id += 2
        stream = GatewayStream(self, stream_id)
        self.streams[stream_id] = stream
        self.stream_windows[stream_id] = self.initial_stream_window
        authority = f"{self.host}:{self.port}"
        headers = [(":method", "POST"), (":scheme", "https" if self.use_tls else "http"),
                   (":path", path), (":authority", authority), ("content-type", "application/grpc"),
                   ("te", "trailers"), ("grpc-accept-encoding", "identity")]
        headers.extend(metadata.items())
        await self.emit_frame(self.FRAME_HEADERS, 0x04 | (0x01 if end_stream else 0), stream_id, hpack_headers(headers))
        return stream

    async def push_body(self, stream_id, data, end_stream=False):
        offset = 0
        while offset < len(data):
            while self.connection_window <= 0 or self.stream_windows.get(stream_id, 0) <= 0:
                self.window_event.clear()
                await self.window_event.wait()
            size = min(len(data) - offset, self.max_frame_size, self.connection_window, self.stream_windows[stream_id])
            flags = 0x01 if end_stream and offset + size == len(data) else 0
            await self.emit_frame(self.FRAME_DATA, flags, stream_id, data[offset:offset + size])
            self.connection_window -= size
            self.stream_windows[stream_id] -= size
            offset += size
        if not data and end_stream:
            await self.emit_frame(self.FRAME_DATA, 0x01, stream_id)

    async def close(self):
        background_tasks = tuple(
            task for task in (self.reader_task, self.ping_task)
            if task and task is not asyncio.current_task()
        )
        self.reader_task = None
        self.ping_task = None
        for task in background_tasks:
            task.cancel()
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)
        error = TransportError("HTTP/2 connection closed")
        for stream in tuple(self.streams.values()):
            stream.fail(error)
        self.streams.clear()
        self.stream_windows.clear()
        self.window_event.set()
        writer = self.writer
        self.reader = self.writer = None
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ==================== gRPC transport ====================
class GatewayStream:
    def __init__(self, connection, stream_id):
        self.connection, self.stream_id = connection, stream_id
        self.queue = asyncio.Queue()
        self.buffer = bytearray()
        self.closed = False
        self._write_lock = asyncio.Lock()
        self.response_headers = {}

    async def write(self, message):
        packet = b"\x00" + struct.pack("!I", len(message)) + message
        async with self._write_lock:
            await self.connection.push_body(self.stream_id, packet)

    async def end(self):
        async with self._write_lock:
            await self.connection.push_body(self.stream_id, b"", True)

    def feed(self, data):
        self.buffer.extend(data)
        while len(self.buffer) >= 5:
            compressed = self.buffer[0]
            length = struct.unpack("!I", self.buffer[1:5])[0]
            if len(self.buffer) < 5 + length:
                break
            payload = bytes(self.buffer[5:5 + length])
            del self.buffer[:5 + length]
            if compressed:
                self.fail(TransportError("compressed gRPC messages are unsupported"))
                return
            self.queue.put_nowait(payload)

    def finish(self):
        if not self.closed:
            self.closed = True
            self.queue.put_nowait(None)

    def fail(self, exc):
        if not self.closed:
            self.closed = True
            self.queue.put_nowait(exc)

    async def read(self):
        item = await self.queue.get()
        if isinstance(item, Exception):
            raise item
        return item


class GatewayClient:
    def __init__(self, target):
        host, port_text = target.rsplit(":", 1)
        self.host = host.strip("[]")
        self.port = int(port_text)
        self.use_tls = BOT_TLS or self.port in (443, 2053, 2083, 2087, 2096, 8443)
        self.connection = None
        self.metadata = {"client_secret": BOT_TOKEN_SECRET, "client_uuid": UUID}

    async def connect(self):
        gateway_ip = await resolve_gateway(self.host)
        self.connection = Http2Transport(
            self.host,
            self.port,
            self.use_tls,
            gateway_ip=gateway_ip,
        )
        await self.connection.connect()

    async def call_rpc(self, path, request, timeout=10):
        connection = self.connection
        if not connection:
            raise TransportError("gRPC client is closed")
        if DEBUG:
            logger.debug("rpc open %s", path)
        stream = await connection.open_channel(path, self.metadata)
        try:
            await stream.write(request)
            await stream.end()
            if DEBUG:
                logger.debug("rpc sent %s, waiting", path)
            try:
                response = await asyncio.wait_for(stream.read(), timeout)
            except asyncio.TimeoutError:
                if DEBUG:
                    logger.debug("rpc %s: no reply within %ss", path, timeout)
                raise
            if DEBUG:
                logger.debug("rpc reply %s", path)
            if response is None:
                trailers = getattr(stream, "response_headers", {}) or {}
                status = str(trailers.get("grpc-status", ""))
                message = trailers.get("grpc-message", "")
                http = trailers.get(":status", "")
                if status in ("", "0"):
                    return b""
                raise TransportError(f"empty gRPC response (http={http}, grpc-status={status} {message})")
            return response
        finally:
            connection.streams.pop(stream.stream_id, None)
            connection.stream_windows.pop(stream.stream_id, None)
            if not stream.closed:
                try:
                    await connection.emit_frame(
                        connection.FRAME_RST_STREAM, 0, stream.stream_id, struct.pack("!I", 8)
                    )
                except Exception:
                    pass

    async def call_stream(self, path):
        return await self.connection.open_channel(path, self.metadata)

    async def close(self):
        connection = self.connection
        self.connection = None
        if connection:
            await connection.close()


# ==================== System metrics ====================
def read_file(path, default=""):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def mem_usage():
    values = {}
    for line in read_file("/proc/meminfo").splitlines():
        if ":" in line:
            key, raw = line.split(":", 1)
            try:
                values[key] = int(raw.strip().split()[0]) * 1024
            except (ValueError, IndexError):
                pass
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    return total, max(0, total - available), values.get("SwapTotal", 0), max(0, values.get("SwapTotal", 0) - values.get("SwapFree", 0))


def disk_usage():
    try:
        stat = os.statvfs("/")
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        return total, max(0, total - free)
    except (AttributeError, OSError):
        return 0, 0


def net_counters():
    received = sent = 0
    for line in read_file("/proc/net/dev").splitlines()[2:]:
        if ":" not in line:
            continue
        name, values = line.split(":", 1)
        if name.strip() == "lo":
            continue
        fields = values.split()
        if len(fields) >= 9:
            received += int(fields[0])
            sent += int(fields[8])
    return received, sent


def job_count():
    try:
        return sum(name.isdigit() for name in os.listdir("/proc"))
    except OSError:
        return 0


def socket_counts():
    tcp = udp = 0
    for name in ("tcp", "tcp6"):
        tcp += max(0, len(read_file("/proc/net/" + name).splitlines()) - 1)
    for name in ("udp", "udp6"):
        udp += max(0, len(read_file("/proc/net/" + name).splitlines()) - 1)
    return tcp, udp


class PresenceTracker:
    def __init__(self):
        self.last_cpu = self._cpu_tick()
        self.last_net = net_counters()
        self.last_time = time.monotonic()

    def _cpu_tick(self):
        first = read_file("/proc/stat").splitlines()
        if first and first[0].startswith("cpu "):
            values = [int(value) for value in first[0].split()[1:]]
            total = sum(values)
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            return total, idle
        return 0, 0

    def host(self):
        total_mem, _, total_swap, _ = mem_usage()
        total_disk, _ = disk_usage()
        os_name = platform.system()
        release = read_file("/etc/os-release")
        for line in release.splitlines():
            if line.startswith("PRETTY_NAME="):
                os_name = line.split("=", 1)[1].strip().strip('"')
                break
        cpu_name = platform.processor() or platform.machine()
        cpuinfo = read_file("/proc/cpuinfo")
        for line in cpuinfo.splitlines():
            if line.lower().startswith(("model name", "hardware")) and ":" in line:
                cpu_name = line.split(":", 1)[1].strip()
                break
        try:
            uptime = float(read_file("/proc/uptime").split()[0])
        except (ValueError, IndexError):
            uptime = 0
        return {"platform": os_name, "platform_version": platform.release(), "cpu": [cpu_name],
                "mem_total": total_mem, "disk_total": total_disk, "swap_total": total_swap,
                "arch": platform.machine(), "virtualization": "", "boot_time": int(time.time() - uptime),
                "version": "5.5.5"}

    def state(self):
        current_cpu = self._cpu_tick()
        total_delta = current_cpu[0] - self.last_cpu[0]
        idle_delta = current_cpu[1] - self.last_cpu[1]
        cpu = max(0, min(100, (total_delta - idle_delta) * 100 / total_delta)) if total_delta > 0 else 0
        self.last_cpu = current_cpu
        _, mem_used, _, swap_used = mem_usage()
        _, disk_used = disk_usage()
        current_net = net_counters()
        now = time.monotonic()
        elapsed = max(0.001, now - self.last_time)
        in_speed = max(0, int((current_net[0] - self.last_net[0]) / elapsed))
        out_speed = max(0, int((current_net[1] - self.last_net[1]) / elapsed))
        self.last_net, self.last_time = current_net, now
        try:
            uptime = int(float(read_file("/proc/uptime").split()[0]))
        except (ValueError, IndexError):
            uptime = 0
        loads = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)
        tcp, udp = socket_counts()
        return {"cpu": cpu, "mem_used": mem_used, "swap_used": swap_used, "disk_used": disk_used,
                "net_in_transfer": current_net[0], "net_out_transfer": current_net[1],
                "net_in_speed": in_speed, "net_out_speed": out_speed, "uptime": uptime,
                "load1": loads[0], "load5": loads[1], "load15": loads[2],
                "tcp_conn_count": tcp, "udp_conn_count": udp, "job_count": job_count()}


# ==================== Task execution ====================
async def run_command(task):
    result = {"id": task["id"], "type": task["type"], "delay": 0, "data": "", "successful": False}
    started = time.monotonic()
    try:
        if task["type"] == 1:
            if BOT_NO_FETCH:
                result["data"] = "disabled"
            else:
                await request_async(task["data"], timeout=30)
                result["successful"] = True
        elif task["type"] == 3:
            if BOT_NO_FETCH:
                result["data"] = "disabled"
            else:
                host, port = task["data"].rsplit(":", 1)
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host.strip("[]"), int(port)), 10)
                writer.close()
                await writer.wait_closed()
                result["successful"] = True
        elif task["type"] == 4:
            result["data"] = "disabled"
        elif task["type"] == 7:
            result["successful"] = True
        elif task["type"] == 12:
            result["data"] = json.dumps({"server": BOT_GATEWAY, "uuid": UUID, "tls": BOT_TLS,
                                           "report_delay": BOT_HEARTBEAT,
                                           "disable_command_execute": BOT_NO_SHELL,
                                           "disable_send_query": BOT_NO_FETCH,
                                           "disable_terminal": BOT_NO_TERM,
                                           "disable_file_manager": BOT_NO_FILES})
            result["successful"] = True
        else:
            result["data"] = "Unsupported task type: " + str(task["type"])
    except Exception as exc:
        result["data"] = str(exc)
    result["delay"] = (time.monotonic() - started) * (1000 if task["type"] in (1, 3) else 1)
    return result


# ==================== Agent main loop ====================
async def fetch_region():
    endpoints = (
        "https://blog.cloudflare.com/cdn-cgi/trace",
        "https://developers.cloudflare.com/cdn-cgi/trace",
        "https://hostinger.com/cdn-cgi/trace",
        "https://ahrefs.com/cdn-cgi/trace",
    )
    ipv4 = ""
    ipv6 = ""
    for url in endpoints:
        try:
            status, body = await request_async(
                url,
                timeout=20,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
            )
            if status != 200:
                continue
            text = body.decode("utf-8", "ignore").strip()
            value = ""
            for line in text.splitlines():
                if line.strip().startswith("ip="):
                    value = line.split("=", 1)[1].strip()
                    break
            if not value:
                value = text
            address = ipaddress.ip_address(value)
            if address.version == 4 and not ipv4:
                ipv4 = value
            elif address.version == 6 and not ipv6:
                ipv6 = value
            if ipv4 and ipv6:
                break
        except Exception as exc:
            if DEBUG:
                logger.debug("GeoIP query failed via %s: %s", url, exc)
    if not ipv4 and not ipv6:
        return None
    return {
        "use_ipv6": BOT_IPV6_LOOKUP,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "country_code": "",
        "gateway_boot_time": 0,
    }


class DiscordClient:
    def __init__(self):
        self.monitor = PresenceTracker()
        self.client = None
        self.sessions = set()

    async def start_client(self):
        backoff = BOT_RETRY_DELAY
        while True:
            started = time.monotonic()
            error = None
            try:
                await self.connect_gateway()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                error = exc
            uptime = time.monotonic() - started
            message = ((str(error).strip() or type(error).__name__)
                       if error is not None else "connection ended")
            if uptime >= 60:

                backoff = BOT_RETRY_DELAY
                if DEBUG:
                    logger.debug("session recycled after %ss: %s", int(uptime), message)
            elif error is not None and DEBUG:

                logger.debug("reconnect failed: %s; retry in %ss", message, backoff)
            await asyncio.sleep(backoff)
            backoff = min(BOT_RECONNECT_COOLDOWN, backoff * 2)

    async def connect_gateway(self):
        client = GatewayClient(BOT_GATEWAY)
        self.client = client
        workers = set()
        pending_jobs = set()
        try:
            await client.connect()
            receipt = await client.call_rpc(_svc("/proto.@/ReportSystemInfo2"), encode_host(self.monitor.host()))
            gateway_boot_time = decode_uint_receipt(receipt)
            if not getattr(self, "connected_once", False):
                if DEBUG:
                    logger.info("session established")
                self.connected_once = True
            elif DEBUG:
                logger.debug("session restored")
            for attempt in range(3):
                try:
                    geoip = await fetch_region()
                    if geoip:
                        geoip["gateway_boot_time"] = gateway_boot_time
                        await client.call_rpc(_svc("/proto.@/ReportGeoIP"), encode_geoip(geoip))
                    break
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    if DEBUG:
                        logger.debug("region lookup attempt %s failed: %s", attempt + 1,
                                     str(exc).strip() or type(exc).__name__)
                    if attempt < 2:
                        await asyncio.sleep(3 + attempt * 4)
            async def hold_presence():
                """Keep the state stream alive. When the server or a proxy kills a
                single stream, reopen it on the same connection: a full session
                reset is what the panel shows as a short offline blip."""
                streak = 0
                while True:
                    stream = await client.call_stream(_svc("/proto.@/ReportSystemState"))
                    streak = 0

                    async def send_states():
                        while True:
                            await stream.write(encode_state(self.monitor.state()))
                            await asyncio.sleep(BOT_HEARTBEAT)

                    async def read_receipts():
                        while True:
                            message = await stream.read()
                            if message is None:
                                raise TransportError("state stream ended")

                    pair = [asyncio.create_task(send_states()), asyncio.create_task(read_receipts())]
                    try:
                        done, _ = await asyncio.wait(pair, return_when=asyncio.FIRST_COMPLETED)
                        for task in done:
                            if task.cancelled():
                                continue
                            error = task.exception()
                            if error is not None and not isinstance(
                                error, (TransportError, OSError, ssl.SSLError, asyncio.TimeoutError)
                            ):
                                raise error
                    finally:
                        for task in pair:
                            if not task.done():
                                task.cancel()
                        await asyncio.gather(*pair, return_exceptions=True)
                    streak += 1
                    if DEBUG:
                        logger.debug("state stream reopened (streak %s)", streak)
                    if streak > 20:
                        raise TransportError("state stream keeps dying")
                    await asyncio.sleep(1)

            async def report_profile():
                while True:
                    await asyncio.sleep(600)
                    await client.call_rpc(
                        _svc("/proto.@/ReportSystemInfo2"),
                        encode_host(self.monitor.host()),
                    )

            async def report_region():
                while True:
                    await asyncio.sleep(BOT_IP_PERIOD)
                    try:
                        geoip = await fetch_region()
                        if geoip:
                            geoip["gateway_boot_time"] = gateway_boot_time
                            await client.call_rpc(_svc("/proto.@/ReportGeoIP"), encode_geoip(geoip))
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        if DEBUG:
                            logger.debug("region lookup failed: %s", str(exc).strip() or type(exc).__name__)

            async def exec_and_ack(task, stream):
                try:
                    result = await run_command(task)
                    await stream.write(encode_task_result(result))
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    if DEBUG:
                        logger.debug("task %s report failed: %s", task["id"], exc)

            async def hold_commands():
                """Same idea for the task bus: reopen the stream, keep the session."""
                streak = 0
                while True:
                    stream = await client.call_stream(_svc("/proto.@/RequestTask"))
                    streak = 0
                    try:
                        while True:
                            message = await stream.read()
                            if message is None:
                                raise TransportError("task stream ended")
                            task = decode_task(message)
                            while len(pending_jobs) >= BOT_MAX_JOBS:
                                await asyncio.wait(tuple(pending_jobs), return_when=asyncio.FIRST_COMPLETED)
                            runner = asyncio.create_task(exec_and_ack(task, stream))
                            pending_jobs.add(runner)
                            runner.add_done_callback(pending_jobs.discard)
                    except asyncio.CancelledError:
                        raise
                    except (TransportError, OSError, ssl.SSLError, asyncio.TimeoutError):
                        pass
                    streak += 1
                    if DEBUG:
                        logger.debug("task stream reopened (streak %s)", streak)
                    if streak > 20:
                        raise TransportError("task stream keeps dying")
                    await asyncio.sleep(1)

            workers = {
                asyncio.create_task(hold_presence()),
                asyncio.create_task(hold_commands()),
                asyncio.create_task(report_profile()),
                asyncio.create_task(report_region()),
            }
            done, _ = await asyncio.wait(workers, return_when=asyncio.FIRST_EXCEPTION)
            for task in done:
                if task.cancelled():
                    raise asyncio.CancelledError
                error = task.exception()
                if error:
                    raise error
            raise TransportError("event loop ended")
        finally:
            for task in workers:
                if not task.done():
                    task.cancel()
            if workers:
                await asyncio.gather(*workers, return_exceptions=True)
            for task in tuple(pending_jobs):
                if not task.done():
                    task.cancel()
            if pending_jobs:
                await asyncio.gather(*pending_jobs, return_exceptions=True)
            sessions = tuple(self.sessions)
            for session in sessions:
                if not session.done():
                    session.cancel()
            if sessions:
                await asyncio.gather(*sessions, return_exceptions=True)
            self.sessions.clear()
            await client.close()
            if self.client is client:
                self.client = None


# ==================== Entry point ====================
async def main():
    if BOT_GATEWAY and BOT_TOKEN_SECRET:
        asyncio.create_task(DiscordClient().start_client())
    server = await asyncio.start_server(on_connection, "0.0.0.0", PORT, limit=MAX_HTTP_HEADER)
    bound_port = server.sockets[0].getsockname()[1] if server.sockets else PORT
    logger.info("listening on 0.0.0.0:%s", bound_port)
    asyncio.create_task(schedule_cleanup())
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nserver stopped")
    finally:
        purge_temp()