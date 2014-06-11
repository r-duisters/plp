Passive LAN Profiler
===

---
One can gather a lot of information about corporate Local Area Network (LAN) environments by passively listening on these networks. This information can be used during the reconnaissance phase of a penetration test.

This repository contains a proof of concept of this technique. The proof of concept parses a pcap capture, stores "interesting" data in a database, creates relationships between the data and generates a report of the gathered information.

At this moment the proof of concept code gathers information from a sample of six broadcast/multicast protocols: mDNS, SMB Browser, DHCP, NBNS, STP and CDP. 

The following report describes the used techniques in more detail: http://www.delaat.net/rp/2010-2011/p43/report.pdf
