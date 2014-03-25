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
local Message = {}


--------------------------------------------------
-- wrietHeader --
--------------------------------------------------
function writeHeader(buffer,pinfo,tree,offset)
    local jgroups_header_id_range = buffer(offset,2)
    local jgroups_header_id = header_id(jgroups_header_id_range:uint())
    subtree:add(f_jgroups_header_id, jgroups_header_id_range, jgroups_header_id)
    offset = offset + 2

    local jgroups_header_magic_number_range = buffer(offset,2)
    local jgroups_header_magic_number = jgroups_header_magic_number_range:uint()
    subtree:add(f_jgroups_header_magic_number, jgroups_header_magic_number_range, jgroups_header_magic_number)
    offset = offset + 2

    local header_id_table = require "protocols.header_id_table"

    -- If the protocol is not supported yet, return data
    if header_id_table[jgroups_header_id] == nil then
        local data_dissector = Dissector.get("data")
        data_dissector:call(buffer(offset):tvb(),pinfo,tree)
        return "not_supported"
    end

    offset = header_id_table[jgroups_header_id](buffer,pinfo,tree,offset)
    
    return offset
end


--------------------------------------------------
-- wrietTo --
--------------------------------------------------
function writeTo(buffer,pinfo,tree,offset,p)
    Util = require "util.Util"
    --for TCP
    if p == "tcp" then
        offset = offset + 4
    end

    local jgroups_version_range = buffer(offset,2)
    local jgroups_version = version_decode(jgroups_version_range:uint())
    subtree:add(f_jgroups_version, jgroups_version_range, jgroups_version)
    offset = offset + 2

    local jgroups_mcast_flag_range = buffer(offset,1)
    local jgroups_mcast_flag = mcastFlag(jgroups_mcast_flag_range:uint())
    subtree:add(f_jgroups_mcast_flag, jgroups_mcast_flag_range, jgroups_mcast_flag)
    offset = offset + 1

    local jgroups_leading_range = buffer(offset,1)
    local jgroups_leading_bits = toBits(jgroups_leading_range:uint(),3)
    local jgroups_leading = leading(jgroups_leading_bits)
    subtree:add(f_jgroups_leading, jgroups_leading_range, jgroups_leading)
    offset = offset + 1

    local jgroups_msg_type_flag_range = buffer(offset,2)
    local jgroups_msg_type_flag = msgTypeFlag(jgroups_msg_type_flag_range:uint())
    subtree:add(f_jgroups_msg_type_flag, jgroups_msg_type_flag_range, jgroups_msg_type_flag)
    offset = offset + 2

    if bit32.band(jgroups_leading_bits[1]) == 1 then
        offset = Util.writeAddress(buffer,pinfo,tree,offset)
    end

    if bit32.band(jgroups_leading_bits[2]) == 1 then
        offset = Util.writeAddress(buffer,pinfo,tree,offset)
    end

    -- buffer -- TODO not string
    if bit32.band(jgroups_leading_bits[3]) == 1 then
        local jgroups_buffer_size_range = buffer(offset,4)
        local jgroups_buffer_size = jgroups_buffer_size_range:uint()
        subtree:add(f_jgroups_buffer_size, jgroups_buffer_size_range, jgroups_buffer_size)
        offset = offset + 4

        local jgroups_buffer_range = buffer(offset,jgroups_buffer_size)
        local jgroups_buffer = jgroups_buffer_range:string()
        subtree:add(f_jgroups_buffer, jgroups_buffer_range, jgroups_buffer)
        offset = offset + jgroups_buffer_size
    end

    local jgroups_headers_size_range = buffer(offset,2)
    local jgroups_headers_size = jgroups_headers_size_range:uint()
    subtree:add(f_jgroups_headers_size, jgroups_headers_size_range, jgroups_headers_size)
    offset = offset + 2

    for i=1,tonumber(jgroups_headers_size) do
        offset = writeHeader(buffer,pinfo,tree,offset)
        if offset == "not_supported" then
            break
        end
    end

end


--------------------------------------------------
-- @@module table@@ --
--------------------------------------------------
function Message.writeHeader(buffer,pinfo,tree,offset)
    return writeHeader(buffer,pinfo,tree,offset)
end

function Message.writeTo(buffer,pinfo,tree,offset,p)
    return writeTo(buffer,pinfo,tree,offset,p)
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return Message
