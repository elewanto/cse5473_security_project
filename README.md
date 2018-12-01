# cse5473_security_project

Implementation of Bleichenbacher and POODLE SSLv3 Padding attack silumation using python. 

MITM Detection
----------------------

https://caddyserver.com/docs/mitm-detection  
	Caddy is based on https://jhalderm.com/pub/papers/interception-ndss17.pdf  (Many smart authors it seems)  
	Github: https://github.com/mholt/caddy  
	look at endsection--inpsired by other projects  

#### Separate Small MITM detection tools
https://github.com/chorn/mitm-detector


#### separate paper --many authors
Detecting and Defeating Advanced Man-In-TheMiddle Attacks against TLS  
http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=6916404


#### Researchers detect SSL MitM attacks, method implemented by Facebook
https://www.scmagazine.com/researchers-detect-ssl-mitm-attacks-method-implemented-by-facebook/article/538136/




Webserver Implementation
-------------------------

#### Simple Python HTTTPS Webserver
https://gist.github.com/dergachev/7028596


POODLE Implementation
----------------------

#### POODLE Security Bulletins
https://www.openssl.org/~bodo/ssl-poodle.pdf  
https://security.googleblog.com/2014/10/this-poodle-bites-exploiting-ssl-30.html

#### POODLE Explanation
https://patzke.org/implementing-the-poodle-attack.html  
https://en.wikipedia.org/wiki/POODLE  
https://www.troyhunt.com/everything-you-need-to-know-about/

#### POODLE POC Resources
http://nerdoholic.org/uploads/dergln/beast_part2/ssl_jun21.pdf  
https://patzke.org/implementing-the-poodle-attack.html  
https://github.com/EiNSTeiN-/poodle  
https://github.com/mpgn/poodle-PoC


Bleichenbacher
----------------------

#### Bleichenbacher Explanation
https://crypto.stackexchange.com/questions/12688/can-you-explain-bleichenbachers-cca-attack-on-pkcs1-v1-5


#### Bleichenbacher paper
http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf

#### Bleichenbacher Simulated Attack Code
https://gist.github.com/vishnuvp/5ab5d1a05fef490e25b7

#### Practical Padding Oracle Attacks on RSA
http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html

#### Bleichenbacher Simulated Attack Code
https://github.com/duesee/bleichenbacher

### Bleichenbacher Simulated Code Between Server and Client
https://github.com/diogt52/bleichenbacher_attack

Understand Concepts 
------------------

#### Ditital Certificates
https://www.sslsupportdesk.com/details-digital-certificate-mean/
