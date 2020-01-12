# cve-2019-3398
## Details
A quick python proof of concept for CVE-2019-3398 confluence vulnerability written in python.

Confluence version 6.12.3, 6.13.3, 6.14.2, and 6.15.1 are affected.

The exploit requires working credentials.
# To use
Edit the `os_username` and `os_password` fields, and possibly the `filename` path depending on the vulnerable server. If the path is set right, `shell.jsp` will be available on the root of the web server.
