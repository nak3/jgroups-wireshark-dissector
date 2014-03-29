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
local STABLE = {}


-- LOCAL --
--------------------------------------------------
-- addressTypeFlag --
--------------------------------------------------
function STABLE_addressTypeFlag(d_pbcastStable_type)
    if d_pbcastStable_type == 1 then
        return "STABLE_GOSSIP"
    elseif d_pbcastStable_type == 2 then
        return "STABILITY"
    else
        return "<unknown>"
    end
end


--------------------------------------------------
-- writeTo --
--------------------------------------------------
STABLE.writeTo = function(buffer,pinfo,subtree,offset)
    Util = require "util.Util"
    obj = "Digest"

    local jgroups_pbcastStable_type_range = buffer(offset,4)
    local jgroups_pbcastStable_type = STABLE_addressTypeFlag(jgroups_pbcastStable_type_range:uint())
    subtree:add(f_jgroups_pbcastStable_type, jgroups_pbcastStable_type_range, jgroups_pbcastStable_type)
    offset = offset + 4
    
    offset = Util.writeStreamable(buffer,pinfo,subtree,offset,obj)
    
    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return STABLE
