-- (c) 2014 Kenjiro NAKAYAMA <nakayamakenjiro at gmail dot com>
--
--
-- Wireshark dissector for JGropus
-- By Kenjiro NAKAYAMA <nakayamakenjiro at gmail dot com>
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

--------------------------------------------------
-- @@module name@@ --
--------------------------------------------------
MERGE3 = {}


--------------------------------------------------
-- writeTo --
--------------------------------------------------
MERGE3.writeTo  = function(buffer,pinfo,tree,offset)
    Util = require "util.Util"

    local jgroups_MERGE3_type_range = buffer(offset,1)
    local jgroups_MERGE3_type = jgroups_MERGE3_type_range:uint()
    subtree:add(f_jgroups_MERGE3_type, jgroups_MERGE3_type_range, jgroups_MERGE3_type)
    offset = offset + 1

    offset = Util.writeViewId(buffer,pinfo,tree,offset)
    offset = Util.writeView(buffer,pinfo,tree,offset)
    offset = Util.writeString(buffer,pinfo,tree,offset)
    offset = Util.writeAddresses(buffer,pinfo,tree,offset)

    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return MERGE3
