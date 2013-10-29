Tinkerforge Wireshark Dissector
===============================

This repository contains a Wireshark dissector for the Tinkerforge
USB and TCP/IP protocol. Find more information `here <http://www.tinkerforge.com/en/doc/Low_Level_Protocols/TCPIP.html>`__.

Installation
------------

This dissector `got included <https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9324>`__
into the official Wireshark `codebase <http://anonsvn.wireshark.org/viewvc/trunk/epan/dissectors/packet-tfp.c>`__
and will be available on the next release of Wireshark (current version is
1.10.2) as a built-in dissector. For older versions one can add and use this
dissector as a built-in or plugin dissector by following the Wireshark
`documentation <http://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html>`__.
