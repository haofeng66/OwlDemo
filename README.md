# OwlDemo
A simple Java program to demonstrate how the Owl protocol works in an elliptic curve setting.

## An example output for using the same passwords (authentication SUCCESSFUL)

************ Public elliptic curve domain parameters ************  
Curve param a (256 bits): ffffffff00000001000000000000000000000000fffffffffffffffffffffffc  
Curve param b (255 bits): 5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b   
Co-factor h (1 bits): 1  
Base point G (33 bytes): 36b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296  
X coord of G (255 bits): 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296  
y coord of G (255 bits): 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5  
Order of the base point n (256 bits): ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551  
Prime field q (256 bits): ffffffff00000001000000000000000000000000ffffffffffffffffffffffff  

User name: Alice  
Server name: Server  
Password used in registration: deadbeef  
Password used in login: deadbeef  

************ Registration ************  

Client sends to Server (over a secure channel)  
username: Alice  
pi: de5c112a4b51a44c46e39aa296e1c104706e9b95177b57d8e915c1f5b7366ee2  
T: 2e25b313441c35fbb095da89c2ca84501b4c4cee8695f57cd6aa9ec05a6b98018  

Server generates the following to complete the client registration  
G*x3: 3c610d13e2366c55e6606452a18c343dffe84598e477cb4d639c156b485a2f20c  
KP{x3}: {V=2aed76484cbe81660537a664115438d6607f795ed14312ae9d396d5e9ccb9847f; r=bafeb0cab1fdb9bb568562edf28f428c670c99cd1ffdcc2b7cd734296fa89d6d}  

************ Login ************  

In the first pass, Client sends to Server   
Username: Alice  
G*x1: 3f5453d2652c9ef3fa8917150b0874bc4704930cf5426fc063e2061f1568c2c19  
G*x2: 3f0b91cd97680fb815ea6e7d6d7c368278f1514dd938f870da4c93a158ba230bd  
KP{x1}: {V=3648555f384c296b9f4fd64c7ac9fce202755ec167e2ee0887becaf00e59f7004; r=3330d3df1a14c65769bda591ad7d2d8e9e45ecb2a7b96ca696db0945333452cc}  
KP{x2}: {V=27e46177ced019b6932cf4d662396ef1c6036dcd5f699461e85c84d989ff8c6ea; r=70db37726802dc8064406868ff2635bb09fdae61f45f8870597e35a04e6d80dd}  

Server checks KP{x1}: OK  
Server checks KP{x2}: OK  

In the second pass, Server sends to Client   
Server name: Server  
G*x3: 3c610d13e2366c55e6606452a18c343dffe84598e477cb4d639c156b485a2f20c  
G*x4: 2ec6515bd342d70373d09366cc72a2230260a075ca0960c41f2534e85b411f4a8  
KP{x3}: {V=2aed76484cbe81660537a664115438d6607f795ed14312ae9d396d5e9ccb9847f; r=bafeb0cab1fdb9bb568562edf28f428c670c99cd1ffdcc2b7cd734296fa89d6d}  
KP{x4}: {V=2160c2ab9dcc808ee3c1294494418839ba494f31bf1766f99ef5778c375a2fe17; r=c4d7e29980462d80d198ec5c80d72e78debf23b36ebd5305a267a1d6ee87f35c}  
Beta: 26fdfda1e4ef2e2426f3a4c095f456733ea93a0bebb7f2421c48cbb1c4b9b4317  
KP{x4*pi}: {V=2871366d041c11c532758248211fe9f799482b50d4fa076b8aace4fce5302e917; r=97ec498b7db39291f683b136ca30a60f713a76c9772d1e654fdc2f98b1b1667f}  

Client checks KP{x3}: OK  
Client checks KP{x4}: OK  
Client checks KP{x4*s}: OK  

In the third pass, Client sends to Server:   
Alpha: 31f3920cdfa6983bbb7f5564dbb38e7237fca3aacfcaf633b06b696657027f63d  
KP{x2*s}: {V=291acda0367e551168f5fd4bf274fc94977efdfc1705fb0102bdd1979301a47b2, r=bc682111532cc1441ea7dbdc54e3c7c90126a4e41caa05f9c6f5ec39b56db81f}  
rValue: 73c257eb50f4c4a5da4aaf270be5284664f172784f4ab9839a48ec4ab2c91fc8  
ClientKCTag (optional): 82fa729138e9b67600780dae3a02105b0090a207a0b969af6a0ce708746f7db8  

Server checks KP{x2*s}: OK  

Client's raw key (ECPoint): 37d5ecff7895bebb8ccf08704ab7f57e32a33b8b9371ae5a9c0eb74ecb1f85372  
Server's raw key (ECPoint): 37d5ecff7895bebb8ccf08704ab7f57e32a33b8b9371ae5a9c0eb74ecb1f85372  
Client's key confirmation key: 63a0f2f56c9a6b14d89e1c6365816faac3fe29989ac03153629ec2345adc0244  
Server's key confirmation key: 63a0f2f56c9a6b14d89e1c6365816faac3fe29989ac03153629ec2345adc0244  

Server checks rValue (for client authentication): OK  
Server checks clientKCTag (for explicit key confirmation): OK  

In the fourth pass, Sever sends to client an optional key confirmation string   
serverKCTag: 6a7965b1af79f182a9ce101d6291c29fbfc85fc48f12a91109b6569eff75ecb8  
Client checks serverKCTag (for explicit key confirmation): OK  

Client's session key: 79f05827f110be846a7ac7f92f9c21632c0c37107fd4df36e882158b922533a5  
Server's session key: 79f05827f110be846a7ac7f92f9c21632c0c37107fd4df36e882158b922533a5  

## An example output for using different passwords (authentication FAILED)  

************ Public elliptic curve domain parameters ************  

Curve param a (256 bits): ffffffff00000001000000000000000000000000fffffffffffffffffffffffc  
Curve param b (255 bits): 5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b  
Co-factor h (1 bits): 1  
Base point G (33 bytes): 36b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296  
X coord of G (255 bits): 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296  
y coord of G (255 bits): 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5  
Order of the base point n (256 bits): ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551  
Prime field q (256 bits): ffffffff00000001000000000000000000000000ffffffffffffffffffffffff  

User name: Alice  
Server name: Server  
Password used in registration: deadbeef  
Password used in login: deadbeef1  

************ Registration ************  

Client sends to Server (over a secure channel)  
username: Alice  
pi: de5c112a4b51a44c46e39aa296e1c104706e9b95177b57d8e915c1f5b7366ee2  
T: 2e25b313441c35fbb095da89c2ca84501b4c4cee8695f57cd6aa9ec05a6b98018  

Server generates the following to complete the client registration  
G*x3: 263e73f90b3c109f893c2593e1a2b3bb2178639a3edaa4571871659c9f20895e7  
KP{x3}: {V=346380e2a92e9cd0121a3f9fc8d5dd013422b0aa492dade0dc15f8dd27993991e; r=f2ba38b587eebff527baf7a56c0414a6f337f9dc44f29366dfac39e9dff59d75}  

************ Login ************  

In the first pass, Client sends to Server   
Username: Alice  
G*x1: 379b32b6ac7bd445deef5448fcbe052959c9946add62a8214b9a401f2fcbb797b  
G*x2: 33219490e2afb5c0e8a22d27e28b6f9e8233bf02ca2e63cc38d1e37b5661ffa66  
KP{x1}: {V=39124065da50e4337b1cefdaa8ac2194521fcbe0987a3fc66ab20ffa4b9745ac6; r=976b5b57b18736c9cc01e55c23bf632b2cf3c53d7d4ea4fe2b47d8bebd1e097f}  
KP{x2}: {V=3e4b1aac707b346e01eea92bd5daf4594eacc5f5f889533810b4e5470cdf83381; r=50174a1c397a2878dadca72ec875050d71062ae315f770b3aaad81b6aabd3735}  

Server checks KP{x1}: OK  
Server checks KP{x2}: OK  

In the second pass, Server sends to Client   
Server name: Server  
G*x3: 263e73f90b3c109f893c2593e1a2b3bb2178639a3edaa4571871659c9f20895e7  
G*x4: 3b0f802c957bac5f17323c65e9d826593b8ed72bb5a388d9b31aa0e7c7610ed11  
KP{x3}: {V=346380e2a92e9cd0121a3f9fc8d5dd013422b0aa492dade0dc15f8dd27993991e; r=f2ba38b587eebff527baf7a56c0414a6f337f9dc44f29366dfac39e9dff59d75}  
KP{x4}: {V=20cb741fe28e263ef144c2104ee1d344c55217e69d2f9fdbd0af3cc5dc0d65310; r=2daf92f3b68f5c4243e95d14f8eb7a8624381168d1ab013668b55e9ea2ab3861}  
Beta: 29f16ee5811c990892529987d6057121c50f26b8dc997eda3299f5ff9c0e41fc1  
KP{x4*pi}: {V=312ffc951ad49f6a200b3f60e7c7f1d1cf0597e6b79eba5daa63766a3fd99b7b3; r=8e9805e7232a99a8f734f01455e3c940ee1355afbb4e4b3de3c81b30b50f0932}  

Client checks KP{x3}: OK  
Client checks KP{x4}: OK  
Client checks KP{x4*s}: OK  

In the third pass, Client sends to Server:   
Alpha: 26baf36eabcb41b7abde5dae60abce0730fd6846027a463fea891c0a6ffcfdebc  
KP{x2*s}: {V=2012bb2de525ca2c7b6382bd84ce2eb43a85942a255c1330f7bd9c4a8a8cdc506, r=1d6911929b658e918e19b168fe3d6361224a3edcd8e745edfe964b2917c89d15}  
rValue: 9f1591580f74c16b01b4a1dbb8b641b7a54c71767758de58b0091ada836d29d5  
ClientKCTag (optional): e5df7c6f0c68539233d9a39f3a88d8e0537d927a20f704af6088b8f04dc3ae1d  

Server checks KP{x2*s}: OK  

Client's raw key (ECPoint): 24950b9d72f0e9b640d986351e1b96aaa1abff7e96352276c6cb8363b059887ee  
Server's raw key (ECPoint): 3723652893cba25d603bb7dc29755e6608a40ffbff5dc67609230eb68c61f5730  
Client's key confirmation key: 7475a3c350aedf8f9a37412fac23822d2d509db64407db00c8cfff51bb48635a  
Server's key confirmation key: fde7667cc7256324726d6eacac3b8865ac75d24b2e0251c160aece2cc9bbcc61  

ERROR: invalid r (client authentication failed).  




