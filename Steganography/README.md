# Steganography

## Intro to Steganography 1

**Challenge**

"This is an introductory challenge for the almighty steganography challenges. The three stages contain very different variants of hidden information. Find them!"

For this challenge we only have an image "chall.jpg".

**Solution**

Because this is a stego challenge and we see nothing interesting on the image, lets see if we find any data within the file.
If we use **"exiftool chall.jpg"** or **"file chall.jpg"**, we find a comment **"alm1ghty\_st3g4n0\_pls\_g1v\_fl4g"**, which looks like a password. This can be usefull later.

One of the standard tools for stegonography challenges is **"stegohide"**, which can extract hidden data within the file.
So we can try **"stegohide extract -sf chall.jpg"**, to extract some hidden data. To do this, stegohide asks for a password. If we use the password from the comment, we found before, stegohide extracts a file **"flag.txt"**.
This file contains the hidden flag **CSCG{Sup3r\_s3cr3t\_d4t4}**

## Intro to Steganography 2

**Challenge**

"This is an introductory challenge for the almighty steganography challenges. The three stages contain very different variants of hidden information. Find them!"

Again, we only get an image "chall.jpg".

**Solution**

The image shows some highrise buildings in the night.
[](writeupfiles/chall2.jpg)

Luckily i already saw this kind of challenge and knew instantly what to do.
So if we search for the original image with google, we see that there are some differences.
The highest tower on the left looks different. The lights in the windows are different from the original.
[](writeupfiles/chall2Edited.jpg)

This is a binary code 
```
010000110101001101000011010001110111101101100001010111110100011001101100001101000110011101111101
```

Converting this binary code to ascii, retuls in the flag: **CSCG{a\_Fl4g}**


## Intro to Steganography 3



