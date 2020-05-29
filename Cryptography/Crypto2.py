import gmpy2
#import binascii
import os
import Crypto.Util.number as number

f = open('message2.txt', 'r')
cipher = gmpy2.mpz(f.read())


N = 11081631875903145989449935723431993312048263659503073501368579288661507666926127398551161494057149306128113773163942639308834214121175806650609216999457699806761832905200688030797211656004392019494461369905299150414106039926917206543955359193966893148964232596310365304968051716316421386564037673515738090636958039103706945349258789436043666088184674948218539196263599899299117746103356732914111330139176914363944699056706536973601851519543254647327613986429683489937828404640743341705415177790924588759219148196121101333618974290049804819348181073769764832469557718828674823915162708288827812462173689965257895702511
print(N)

e = 65537
p = 105269330176947292996638200435938306898008923026214454261833875185727477089897046111427146733705930821830266909665628457524081078905360676252447567252776868229878866771906188152589974886284283170888631961882151644823439854179072943695999068501018297820499189273623372907923121271707038222250931356234064474919
q = 105269330176947292996638200435938306898008923026214454261833875185727477089897046111427146733705930821830266909665628457524081078905360676252447567252776868229878866771906188152589974886284283170888631961882151644823439854179072943695999068501018297820499189273623372907923121271707038222250931356234064574969

assert(p*q == N)
phi = (p-1)*(q-1)
d = gmpy2.divm(1,e,phi)
plaintext = gmpy2.powmod(cipher, d, N)
print(number.long_to_bytes(plaintext))

