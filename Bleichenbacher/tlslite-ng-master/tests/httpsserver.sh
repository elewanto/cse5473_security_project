#!/bin/sh
python ../scripts/tls.py server -k "../tests/serverX509Key.pem" -c "../tests/serverX509Cert.pem" -t "../tests/TACK1.pem" 10.1.2.5:443
