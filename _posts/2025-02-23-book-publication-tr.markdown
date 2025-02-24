---
title:  "MD MZ Book: translations and publication"
date:   2025-02-23 02:00:00 +0200
header:
  teaser: "/assets/images/147/2025-02-24_14-27.png"
categories:
  - book
tags:
  - red team
  - windows
  - linux
  - malware
  - book
  - research
---

﷽

Hello, cybersecurity enthusiasts and white hackers!        

![malware](/assets/images/147/2025-02-24_14-27.png){:class="img-responsive"}    

This is a very short post. I just want to please my readers, colleagues and friends. I posted the source code of the MD MZ book:      

![malware](/assets/images/147/2025-02-24_14-30.png){:class="img-responsive"}    

### versions and translations

Main github repo with translations: [https://github.com/cocomelonc/mdmz_book](https://github.com/cocomelonc/mdmz_book)    
[MD MZ Book first version (2022)](https://cocomelonc.github.io/book/2022/07/16/mybook.html)     
[MD MZ Book second version (2024)](https://cocomelonc.github.io/book/2024/11/29/mybook-2.html)      

This repository was created at the request of my readers to fix errors and create translations into other languages.    

You are welcome to contribute and make pull requests =^..^=!     

Translation into Russian (first few chapters), Turkish (390 pages left) and Portuguese (many thanks to [Joas A Santos](https://github.com/CyberSecurityUP)) languages ​​has begun! =^..^=     

### create pdf

Use [pandoc](https://github.com/jgm/pandoc) command:    

```bash
pandoc -f markdown-implicit_figures --pdf-engine=xelatex -V mainfont="Amiri" -V colorlinks=true -V linkcolor=blue -o mdmz_book.pdf 1-intro.md 2-maldev.md .... 101-finall.md --mathjax
```

Main font:     

[Amiri](https://fonts.google.com/specimen/Amiri)      

### donations and publication

The translation of this book into Turkish is currently underway. Thanks to my friends from Kazakh students community from Turkey.     

You can send donations via [paypal](https://paypal.me/cocomelonc/)    

**All funds raised go towards publishing the hard copy (paper version) of this book (Turkish language). According to my calculations, the first 100 copies will cost almost $5,000.**

Other books:     

[Malware in the Wild Book (2023)](https://cocomelonc.github.io/book/2023/12/13/malwild-book.html)     
[Malware Development for Ethical Hackers (Packt, 2024)](https://github.com/PacktPublishing/Malware-Development-for-Ethical-Hackers/)     
