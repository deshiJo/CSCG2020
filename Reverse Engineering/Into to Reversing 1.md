# Intro to Reversing 1 

This is the first reversing Challenge with the difficulty baby.

As always try strings at first, which shows us the password immidiately in this challenge.
So the response from **"strings ./rev1"** contains the following output:
> Give me your password: 
y0u_5h3ll_p455    
Thats the right password!

Now if we running the binary and passing the password **"y0u_5h3ll_p455"**, we get the flag:
**CSCG{ez_pz_reversing_squ33zy}**

To avoid this security issue, the password could be placed on the server side (for example placed within a file) or the password comparison, within the binary, could use only the hashed password.
