# Web

## StayWoke Shop

**Challenge**

"Are you missing some essential items that were sold out in your local supermarket? You can easily stock up on these in my shop:
http://staywoke.hax1.allesctf.net/"

**Solution**

The Challenge is a web shop, which offers different products for 1€ each. 
These can be added to the shopping cart. In addition, we receive a 20% discount coupon through a scrolling news text (**I<3CORONA**). 

So let's search for a weak point. The coupon code seems to be a good starting point. 
Lets start burp and try to play around with the post and get requests of the shop.
My first thought was posting the same coupon multple times to the server, but this didnt change my wallet ballance or anything else.

While playing around with the shop i relized that the discount amount of the coupon was calculates from the current cart balance.
If you have a shopping card with a sum of product cost of 10€, and you use the discount coupon, the "product" **"coupon"** is added to you card.
This product now has costs **"-2€"**. If we remove now the products from our current cart, this amount remains unchanged.
This allows us to buy any of these products. 
Unfortunately buying one of these Products does not give us the flag.
Also the cart is limited to an amount of 10 products so we cant buy all at once.

So lets keep looking for something odd.

While looking at the intercepted requests in burp i relized that the products are indexed with numbers.
I added the product get-request to the repeater and tried the different numbers to see if there is any hidden product.
And yes, there is a product "flag" at the index 1 (GET /products/1 HTTP/1.1), which costs 1337€:

![](writeupfiles/flagProduct.png)

The rest is pretty easy.
I intercepted a product request of an arbitrary product with burp and changed the requested product index to 1.
Now we have one flag product in our cart.
The next step is adding 10 of these flag products to the cart and use the coupon.
With the coupon we now have 20% of the current costs as a negative value in the cart.
Remove the flags until the balance is high enough to buy a flag.
Now only hit the buy-botton while using the payment option "w0kecoint" with an arbitrary account number.

This will lead us to the order conformation which show us the flag: **CSCG{c00l\_k1ds\_st4y\_@\_/home/}**


To avoid this security issue the discount has to be calculated everytime the cart has changed.
