# pansi
Poor man's ansible, a command line SSH helper tool.

It's just a screwdriver, not a set of tools you have to learn about. 

what it can do :

0. expect is used to reduce interactive requirement.
1. run command remotely
2. ship and run script remotely
3. run against multiple servers in parallel
4. interactive (no parallel)

For people who use SSH a lot. 

In [bin](https://github.com/laowangv5/pansi/tree/master/bin) you can download the binary version which is wrapped by PyInstaller. With this you can save some time without having to setup python environment.  I build them on a rather old server so I suppose it would run well on most Linux servers.

In [examples](https://github.com/laowangv5/pansi/tree/master/examples) there're some simple examples.  Basically pansi follows the way how you use ssh --  simplify the interactive steps with expect(pexpect) and allow you run in specified parallel level. 
