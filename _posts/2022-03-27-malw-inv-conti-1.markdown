---
title:  "Conti ransomware source code investigation - part 1."
date:   2022-03-27 10:00:00 +0600
header:
  teaser: "/assets/images/46/2022-03-30_07-49.png"
categories:
  - investigation
tags:
  - ransomware
  - windows
  - malware
  - red team
  - evasion
  - conti
---

﷽

Hello, cybersecurity enthusiasts and white hackers!

![conti](/assets/images/46/2022-03-30_07-49.png){:class="img-responsive"}    

A Ukrainian security researcher has leaked newer malware source code from the Conti ransomware operation in revenge for the cybercriminals siding with Russia on the invasion of Ukraine.    

![conti](/assets/images/46/2022-03-30_08-09.png){:class="img-responsive"}    

As you can see the last modified dates being January 25th, 2021.   

### what's Conti ransomware?    

ContiLocker is a ransomware developed by the Conti Ransomware Gang, a Russian-speaking criminal collective with suspected links with Russian security agencies. Conti is also operates a ransomware-as-a-service (RaaS) business model.    

### structure   

The source code leak is a Visual Studio solution (contains `conti_v3.sln`):   

![conti](/assets/images/46/2022-03-29_23-30.png){:class="img-responsive"}    

that allows anyone with access to compile the ransomware locker:    

![conti](/assets/images/46/2022-03-29_23-36.png){:class="img-responsive"}    

and decryptor:    

![conti](/assets/images/46/2022-03-29_23-49.png){:class="img-responsive"}    

### AV engines evasion    

The first thing that usually attracts me to professionally written malware is the action by which this malware itself evasion AV engines and hides its activity.    

To see the mechanism of communication with WinAPI, I look in the folder `api`:    

![conti](/assets/images/46/2022-03-29_23-51.png){:class="img-responsive"}    

So, looking at the file `getapi.cpp`. First of all see:   

![conti](/assets/images/46/2022-03-29_23-54.png){:class="img-responsive"}    

As you can see, to convert RVA (Relative Virtual Address) to VA (Virtual Address) conti used this macro.    

Then, find function `GetApiAddr` which find Windows API function address by comparing it's hash:    

![conti](/assets/images/46/2022-03-29_23-56.png){:class="img-responsive"}    

that is, Conti uses one of the simplest but effective AV engines bypass tricks, I wrote about this in a previous [post](/tutorial/2022/03/22/simple-av-evasion-5.html).    

And what hashing algorithm is used by conti?    

![conti](/assets/images/46/2022-03-29_23-56_1.png){:class="img-responsive"}    

![conti](/assets/images/46/2022-03-30_00-00.png){:class="img-responsive"}    

*MurmurHash* is a non-cryptographic hash function and was [written by Austin Appleby](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp).    

After that, the `api` module is invoked to execute an anti-sandbox technique with the purpose of disable all the possible hooking's on known DLLs. In fact, the following DLLs are loaded through the just resolved `LoadLibraryA` API:    

![conti](/assets/images/46/2022-03-30_00-06.png){:class="img-responsive"}    

### threading

What about module `threadpool`?. Each thread allocates its own buffer for the upcoming encryption and initialize its own cryptography context through the `CryptAcquireContextA` API and an RSA public key.:    

![conti](/assets/images/46/2022-03-30_07-19.png){:class="img-responsive"}    

Then, each thread waits in an infinite loop for a task in the `TaskList` queue. In case a new task is available, the filename to encrypt is extracted from the task:    

![conti](/assets/images/46/2022-03-30_10-34.png){:class="img-responsive"}    

### encryption    

The encryption for a specific file starts with a random key generation using the  `CryptGenRandom` API:    

![conti](/assets/images/46/2022-03-30_10-39.png){:class="img-responsive"}    

of a `32`-bytes key and another random generation of an `8`-bytes IV.

And as you can see, conti used [ChaCha](https://en.wikipedia.org/wiki/Salsa20) stream cipher which developed by [D.J.Bernstein](https://en.wikipedia.org/wiki/Daniel_J._Bernstein).    

`CheckForDataBases` method is invoked to check for a possible full or partial encryption:

![conti](/assets/images/46/2022-03-30_10-47.png){:class="img-responsive"}    

![conti](/assets/images/46/2022-03-30_10-56.png){:class="img-responsive"}    

against the following extensions:    

`.4dd, .4dl, .accdb, .accdc, .accde, .accdr, .accdt, .accft, .adb, .ade, .adf, .adp, .arc, .ora, .alf, .ask, .btr, .bdf, .cat, .cdb, .ckp, .cma, .cpd, .dacpac, .dad, .dadiagrams, .daschema, .db, .db-shm, .db-wal, .db3, .dbc, .dbf, .dbs, .dbt, .dbv, .dbx, .dcb, .dct, .dcx, .ddl, .dlis, .dp1, .dqy, .dsk, .dsn, .dtsx, .dxl, .eco, .ecx, .edb, .epim, .exb, .fcd, .fdb, .fic, .fmp, .fmp12, .fmpsl, .fol, .fp3, .fp4, .fp5, .fp7, .fpt, .frm, .gdb, .grdb, .gwi, .hdb, .his, .ib, .idb, .ihx, .itdb, .itw, .jet, .jtx, .kdb, .kexi, .kexic, .kexis, .lgc, .lwx, .maf, .maq, .mar, .mas.mav, .mdb, .mdf, .mpd, .mrg, .mud, .mwb, .myd, .ndf, .nnt, .nrmlib, .ns2, .ns3,.ns4, .nsf, .nv, .nv2, .nwdb, .nyf, .odb, .ogy, .orx, .owc, .p96, .p97, .pan, .pdb, .p dm, .pnz, .qry, .qvd, .rbf, .rctd, .rod, .rodx, .rpd, .rsd, .sas7bdat, .sbf, .scx, .sdb, .sdc, .sdf, .sis, .spg, .sql, .sqlite, .sqlite3, .sqlitedb, .te, .temx, .tmd, .tps, .trc, .trm, .udb, .udl, .usr, .v12, .vis, .vpd, .vvv, .wdb, .wmdb, .wrk, .xdb, .xld, .xmlff, .abcddb, .abs, .abx, .accdw, .adn, .db2, .fm5, .hjt, .icg, .icr, .kdb, .lut, .maw, .mdn, .mdt`    

And `CheckForVirtualMachines` method is invoked to check for a possible partial encryption (`20%`):    

![conti](/assets/images/46/2022-03-30_10-53.png){:class="img-responsive"}    

![conti](/assets/images/46/2022-03-30_10-55.png){:class="img-responsive"}    

the following extensions:    

`vdi, .vhd, .vmdk, .pvm, .vmem, .vmsn, .vmsd, .nvram, .vmx, .raw, .qcow2, .subvol, .bin, .vsv, .avhd, .vmrs, .vhdx, .avdx, .vmcx, .iso`    

and in other cases, the following pattern is followed:   

- if the file size is lower than `1048576 bytes (1.04 GB)` - perform a full encryption
- if the file size is `< 5242880 bytes (5.24 GB)`  and `> 1048576 bytes (1.04 GB)` - partial encryption: only headers    

![conti](/assets/images/46/2022-03-30_10-58.png){:class="img-responsive"}    

else, `50%` partial encryption:   

![conti](/assets/images/46/2022-03-30_11-07.png){:class="img-responsive"}    

![conti](/assets/images/46/2022-03-30_11-09.png){:class="img-responsive"}    

### obfuscation

In addition, an interesting module was found in the source codes: `obfuscation`:    

![conti](/assets/images/46/2022-03-30_10-13.png){:class="img-responsive"}    

which can generate obfuscated code via [ADVObfuscator](https://github.com/andrivet/ADVobfuscator). For example strings:    

![conti](/assets/images/46/2022-03-30_00-15.png){:class="img-responsive"}    

That's all today. In the next part I will investigate `network_scanner` and `filesystem` modules.    

### conclusion   

On `February 25th, 2022`, Conti released a statement of full support for the Russian government - coupled with a stern warning addressed at anyone who might consider retaliating against Russia via digital warfare.    

![conti](/assets/images/46/conti-1.jpg){:class="img-responsive"}    

ContiLeaks is a turning point in the cybercrime ecosystem, and in this case, we can expect a lot of changes in how cybercriminal organizations operate. From the one side less mature cybercriminal orgs might be very powerful and instead more sophischated gangs will learn from Conti's mistakes.    

I hope this post spreads awareness to the blue teamers of this interesting malware techniques, and adds a weapon to the red teamers arsenal.      

[Carbanak](https://en.wikipedia.org/wiki/Carbanak)    
[GetApiAddr implementation in Carberp malware](https://github.com/hryuk/Carberp/blob/master/source%20-%20absource/pro/all%20source/RemoteCtl/DrClient/GetApi.cpp)    
[Carbanak source code](https://github.com/Aekras1a/Updated-Carbanak-Source-with-Plugins)    
[MurmurHash by Austin Appleby](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp)    
[ADVObfuscator](https://github.com/andrivet/ADVobfuscator)    
[ChaCha cipher](https://en.wikipedia.org/wiki/Salsa20)    
[theZoo repo in Github](https://github.com/ytisf/theZoo)    

> This is a practical case for educational purposes only.      

Thanks for your time happy hacking and good bye!   
*PS. All drawings and screenshots are mine*
