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
local RSVP = {}


-- LOCAL --
--------------------------------------------------
-- RSVPtype2String --
--------------------------------------------------
function RSVPtype2String(RSVP_type)
    result = ""
    if RSVP_type == 1 then
        result = "REQ"
    elseif RSVP_type == 2 then
        result = "REQ-ONLY"
    elseif RSVP_type == 3 then
        result = "RSP"
    else
        result = "unknown"
    end
    return result
end


--------------------------------------------------
-- writeTo --
--------------------------------------------------
RSVP.writeTo = function(buffer,pinfo,subtree,offset)
    local jgroups_RSVP_type_range = buffer(offset,1)
    local jgroups_RSVP_type = RSVPtype2String(jgroups_RSVP_type_range:uint())
    subtree:add(f_jgroups_RSVP_type, jgroups_RSVP_type_range, jgroups_RSVP_type)
    offset = offset + 1

    local jgroups_RSVP_Id_range = buffer(offset,2)
    local jgroups_RSVP_Id = jgroups_RSVP_Id_range:uint()
    subtree:add(f_jgroups_RSVP_Id, jgroups_RSVP_Id_range, jgroups_RSVP_Id)
    offset = offset + 2

    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return RSVP
