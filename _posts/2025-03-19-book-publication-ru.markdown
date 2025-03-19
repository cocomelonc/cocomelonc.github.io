---
title:  "MD MZ Book: Russian translation"
date:   2025-03-19 02:00:00 +0200
header:
  teaser: "/assets/images/150/2025-03-19_09-17.png"
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

![malware](/assets/images/150/2025-03-19_09-17.png){:class="img-responsive"}    

This is a very short post. I just want to please my readers, colleagues and friends. translation of MD MZ book to Russian language is finished:      

![malware](/assets/images/150/MD-MZ-2nd-edition-ru.png){:class="img-responsive"}    

### versions and translations

Main github repo with translations: [https://github.com/cocomelonc/mdmz_book](https://github.com/cocomelonc/mdmz_book)    
[MD MZ Book first version (2022)](https://cocomelonc.github.io/book/2022/07/16/mybook.html)     
[MD MZ Book second version (2024)](https://cocomelonc.github.io/book/2024/11/29/mybook-2.html)      

This repository was created at the request of my readers to fix errors and create translations into other languages.    

You are welcome to contribute and make pull requests =^..^=!     

Translation into Albanian (first few chapters) and Portuguese (many thanks to [Joas A Santos](https://github.com/CyberSecurityUP)) languages ​​has begun! =^..^=     

### create pdf

Use [pandoc](https://github.com/jgm/pandoc) command:    

```bash
pandoc -f markdown-implicit_figures --pdf-engine=xelatex -V mainfont="Amiri" -V colorlinks=true -V linkcolor=blue -o mdmz_book.pdf 1-intro.md 2-maldev.md .... 101-finall.md --mathjax
```

Main font:     

[Amiri](https://fonts.google.com/specimen/Amiri)      

But for the Russian language I have some issues. First one is with different fonts: for Russian Cyrillic and for Arabic. The second problem is with displaying comments in code blocks in Russian, so I left them in this version as in the original - in English (I generally consider writing comments in code in languages ​​other than English to be very bad form).

So, I my pandoc command for russian is little bit different:    

```bash
pandoc -f markdown-implicit_figures --pdf-engine=xelatex -V --include-in-header=header.tex -V colorlinks=true -V linkcolor=blue -o mdmz_book.pdf 1-intro.md 2-maldev.md .... 101-finall.md --mathjax
```

and file `header.tex` with the following options:    

```tex
\usepackage{fontspec}
\setmainfont{Fira Mono}
\newfontfamily\arabicfont[Script=Arabic]{Amiri}

\usepackage{babel}
\babelprovide[import, main]{russian}
\babelprovide[import]{arabic}

\babelfont[russian]{rm}{Courier New}
\babelfont[arabic]{rm}{Amiri}
```

and some issues with Arabic ligatures, may Allah forgive me. I had to write in Arabic font from left to right but when the file is generated everything works out fine:     

﷽

Finally you can download Russian PDF from my telegram channel:     

[https://t.me/maldevcc/53](https://t.me/maldevcc/53)     

### donations and publication

You can send donations via [paypal](https://paypal.me/cocomelonc/)    

As I wrote before, **All funds raised go towards publishing the hard copy (paper version) of this book (Russian language). According to my calculations, the first 100 copies will cost almost $4,000-5,000. I continue my fundraising campaign**

Other books:     

[Malware in the Wild Book (2023)](https://cocomelonc.github.io/book/2023/12/13/malwild-book.html)     
[Malware Development for Ethical Hackers (Packt, 2024)](https://github.com/PacktPublishing/Malware-Development-for-Ethical-Hackers/)     
