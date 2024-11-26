#!/bin/tcsh -f

set THIS=`realpath ${0}`;
set DIR=`dirname ${THIS}`;

mv "${DIR}/my.php" 

echo 'phpservice_enable="YES"' >> /etc/rc.conf