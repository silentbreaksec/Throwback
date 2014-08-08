Throwback
=========

HTTP/S Beaconing Implant


1. Run the python script to encode strings.
python tbManger.py encode http://mydomain.com/index.php

http://mydomain.com/index.php -> {57,37,37,33,107,126,126,60,40,53,62,60,48,56,63,127,50,62,60,126,56,63,53,52,41,127,33,57,33}

Note: Don't forget to add ,-1 to end of the integer array for an LP. So the above would become. 

{57,37,37,33,107,126,126,60,40,53,62,60,48,56,63,127,50,62,60,126,56,63,53,52,41,127,33,57,33,-1}

2. Update DNSARRAY to reflect the number of LPs listed in DNSCODE array.

3. Compile!

4. Setup ThrowbackLP.
