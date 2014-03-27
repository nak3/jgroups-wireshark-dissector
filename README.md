jgroups-wireshark-dissector
===========================

jgroups-wireshark-dissector implements JGroups as described at http://www.jgroups.org/.

![Screen Sample](/demo/screenshot/wireshark-jgroups-dissector-sample-screenshot.png)

Supported Version
---------------------------
* JGroups 3.2.12 (which is included in JBoss EAP 6)

See: `supported_version.lua`


Environment
--------------------------
* wireshark 1.11.3 (tested wireshark-1.11.3-rc1-2076-gda83ead from master)
* lua > 5.2


Implemented protocols (still a work in progress)
--------------------------
See: `protocols/header_id_table.lua`


Enable the plugin
--------------------------

**MEMO**: If you are not using wireshark 1.11.3, install it first. See the following Build and Install section.

    sudo cp -r jgroups-dissector /PATH/TO/YOUR/WIRESHARK/GLOBAL_PLUGIN/
    (eg. sudo cp -r jgroups-dissector /usr/local/lib/wireshark/plugins/1.11.3/)

Add following line to the init.lua

`dofile("jgroups-dissector/jgroups-dissector.lua")`

(Optional) Build and Install Wireshark 1.11.3 
--------------------------

#### Fedora 20


This is a build and istall sample process.

    git clone https://code.wireshark.org/review/wireshark
    cd wireshark-$(version)
    ./autogen.sh
    ./configure --enable-setcap-install --enable-warnings-as-errors=no --with-gtk2=yes --with-gtk3=no --with-lua

NOTE: [Fedora 20 cannot build with gtk3](http://www.wireshark.org/lists/wireshark-dev/201312/msg00233.html)

    make
    sudo make install

NOTE: [**Don't run as root user** ](https://blog.wireshark.org/2010/02/running-wireshark-as-you/)
