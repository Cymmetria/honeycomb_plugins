# MICROS honeypot
Cymmetria Research, 2018.

https://www.cymmetria.com/

Written by: Omer Cohen (@omercnet)
Special thanks: Imri Goldberg (@lorgandon), Itamar Sher, Nadav Lev

Contact: research@cymmetria.com

MICROS Honeypot is a low interaction honeypot to detect CVE-2018-2636 in the Oracle Hospitality Simphony component of Oracle Hospitality Applications (MICROS). This is a directory traversal vulnerability. The honeypots does a simple simulation of the MICROS server and will allow attackers to use the vulnerability to "steal files", and will report of such attempts.

It is released under the MIT license for the use of the community, pull requests are welcome!


# Usage

* Run without parameters to listen on default port (8080):

    > python micros_server.py

* Run with --help to see other command line parameters


See also
--------

https://cymmetria.com/blog/honeypots-for-oracle-vulnerabilities/

http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-2636

Please consider trying out the MazeRunner Community Edition, the free version of our cyber deception platform.
https://community.cymmetria.com/
