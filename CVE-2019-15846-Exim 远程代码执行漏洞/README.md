Exim CVE-2019-15846
===================

PoC materials to exploit CVE-2019-15846. Blogpost explaining the PoC is
available on
[Synacktiv Blog](https://www.synacktiv.com/posts/exploit/scraps-of-notes-on-exploiting-exim-vulnerabilities.html).

This PoC help generate spool files used exploit a heap overflow in exim.

Two example spool files are given in [1i7Jgy-0002dD-Pb-D](1i7Jgy-0002dD-Pb-D)
and [1i7Jgy-0002dD-Pb-H](1i7Jgy-0002dD-Pb-H).

A specialy crafted spool header file can be generated with
[exgen.py](exgen.py).
