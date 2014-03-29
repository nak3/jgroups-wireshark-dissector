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
local UNICAST2 = {}


-- LOCAL --
--------------------------------------------------
-- msgTypeFlag --
--------------------------------------------------
function UNICAST2Type(UNICAST2_Type)
    result = ""
    if UNICAST2_Type == 0 then
        result = "DATA"
    elseif UNICAST2_Type == 1 then
        result = "XMIT_REQ"
    elseif UNICAST2_Type == 2 then
        result = "SEND_FIRSTSEQNO"
    elseif UNICAST2_Type == 3 then
        result = "STABLE"
    elseif UNICAST2_Type == 4 then
        result = "ACK"
    end
    return result
end


--------------------------------------------------
-- writeTo --
--------------------------------------------------
UNICAST2.writeTo = function(buffer,pinfo,subtree,offset)

    local jgroups_Unicast2_type_range = buffer(offset,1)
    local jgroups_Unicast2_type = UNICAST2Type(jgroups_Unicast2_type_range:uint())
    subtree:add(f_jgroups_Unicast2_type, jgroups_Unicast2_type_range, jgroups_Unicast2_type)
    offset = offset + 1

    if jgroups_Unicast2_type == "DATA" then
        Util = require "util.Util"
        offset = Util.writeLong(buffer,pinfo,subtree,offset)

        -- conn_id --
        local jgroups_conn_id_range = buffer(offset,2)
        local jgroups_conn_id = jgroups_conn_id_range:uint()
        subtree:add(f_jgroups_conn_id, jgroups_conn_id_range, jgroups_conn_id)
        offset = offset + 2

        -- mark as first --
        local jgroups_flag_as_first_range = buffer(offset,1)
        local jgroups_flag_as_first = Boolean(jgroups_flag_as_first_range:uint())
        subtree:add(f_jgroups_flag_as_first, jgroups_flag_as_first_range, jgroups_flag_as_first)
        offset = offset + 1

    elseif jgroups_Unicast2_type == "XMIT_REQ" then
        -- Nothing todo --

    elseif jgroups_Unicast2_type == "STABLE" then
        Util = require "util.Util"
        offset = Util.writeLongSequence(buffer,pinfo,subtree,offset)

        -- conn_id --
        local jgroups_conn_id_range = buffer(offset,2)
        local jgroups_conn_id = jgroups_conn_id_range:uint()
        subtree:add(f_jgroups_conn_id, jgroups_conn_id_range, jgroups_conn_id)
        offset = offset + 2

    elseif jgroups_Unicast2_type == "SEND_FIRSTSEQNO" then
        Util = require "util.Util"
        offset = Util.writeLong(buffer,pinfo,subtree,offset)

    elseif jgroups_Unicast2_type == "ACK" then
        Util = require "util.Util"
        offset = Util.writeLong(buffer,pinfo,subtree,offset)

        -- conn_id --
        local jgroups_conn_id_range = buffer(offset,1)
        local jgroups_conn_id = jgroups_conn_id_range:uint()
        subtree:add(f_jgroups_conn_id, jgroups_conn_id_range, jgroups_conn_id)
        offset = offset + 2
    end

    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return UNICAST2
