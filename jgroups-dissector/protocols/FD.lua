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
local FD = {}


-- LOCAL --
--------------------------------------------------
-- FDtype2String--
--------------------------------------------------
function FDtype2String(FD_type)
    result = ""
    if FD_type == 0 then
        result = "HEARTBEAT"
    elseif FD_type == 1 then
        result = "HEARTBEAT_ACK"
    elseif FD_type == 2 then
        result = "SUSPECT"
    else
        result = "unknown"
    end
    return result
end

--------------------------------------------------
-- writeTo --
--------------------------------------------------
FD.writeTo = function(buffer,pinfo,tree,offset)
    Util = require "util.Util"

    local jgroups_FD_type_range = buffer(offset,1)
    local jgroups_FD_type = FDtype2String(jgroups_FD_type_range:uint())
    subtree:add(f_jgroups_FD_type, jgroups_FD_type_range, jgroups_FD_type)
    offset = offset + 1

    offset = Util.writeAddresses(buffer,pinfo,tree,offset)
    offset = Util.writeAddress(buffer,pinfo,tree,offset)

    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return FD
