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
Util = {}


--------------------------------------------------
-- writeAddress --
--------------------------------------------------
Util.writeAddress = function(buffer,pinfo,subtree,offset)
    local jgroups_address_type_flag_range = buffer(offset,1)
    local jgroups_address_type_flag = addressTypeFlag(jgroups_address_type_flag_range:uint())
    subtree:add(f_jgroups_address_type_flag, jgroups_address_type_flag_range, jgroups_address_type_flag)
    offset = offset + 1
    
    if jgroups_address_type_flag == "NULL" then
        return offset
    end
    
    --  address.uuid_writeTo --
    if jgroups_address_type_flag == "UUID_ADDR"
    or jgroups_address_type_flag == "SITE_MASTER" then
        UUID = require "util.UUID"
        offset = UUID.writeTo(buffer,pinfo,subtree,offset)
    elseif jgroups_address_type_flag == "SITE_UUID" then
        SiteUUID = require "protocols.relay.SiteUUID"
        offset = SiteUUID.writeTo(buffer,pinfo,subtree,offset)

    elseif jgroups_address_type_flag == "IP_ADDR" then

        IpAddress = require "stack.IpAddress"
        offset = IpAddress.writeTo(buffer,pinfo,subtree,offset)

    else
        offset = offset
    end

    return offset
end


--------------------------------------------------
-- writeAddresses --
--------------------------------------------------
Util.writeAddresses = function(buffer,pinfo,subtree,offset)
    -- TODO
    local jgroups_member_size_range = buffer(offset,2)
    local jgroups_member_size = jgroups_member_size_range:uint()
    subtree:add(f_jgroups_member_size, jgroups_member_size_range, jgroups_member_size)
    offset = offset + 2

    -- TODO no member
    if tonumber(jgroups_member_size) == 65535 then
        return offset
    else
        for i=1,tonumber(jgroups_member_size) do
            offset = Util.writeAddress(buffer,pinfo,subtree,offset)
        end
    end

    return offset
end

--------------------------------------------------
-- writeViewId --
--------------------------------------------------
Util.writeViewId = function(buffer,pinfo,subtree,offset)
    local jgroups_write_boolean_range = buffer(offset,1)
    local jgroups_write_boolean_b = jgroups_write_boolean_range:uint()
    local jgroups_write_boolean = Boolean(jgroups_write_boolean_b)
    subtree:add(f_jgroups_write_boolean, jgroups_write_boolean_range, jgroups_write_boolean)
    offset = offset + 1
    
    if jgroups_write_boolean == "True" then
        ViewId = require "ViewId"
        offset = ViewId.writeTo(buffer,pinfo,subtree,offset)
    end

    return offset
end


--------------------------------------------------
-- writeView --
--------------------------------------------------
Util.writeView = function(buffer,pinfo,subtree,offset)

    local jgroups_write_boolean_range = buffer(offset,1)
    local jgroups_write_boolean_b = jgroups_write_boolean_range:uint()
    local jgroups_write_boolean = Boolean(jgroups_write_boolean_b)
    subtree:add(f_jgroups_write_boolean, jgroups_write_boolean_range, jgroups_write_boolean)
    offset = offset + 1
    
    if jgroups_write_boolean == "False" then
        return offset
    elseif jgroups_write_boolean == "True" then
        local jgroups_write_boolean_range = buffer(offset,1)
        local jgroups_write_boolean_b = jgroups_write_boolean_range:uint()
        local jgroups_write_boolean = Boolean(jgroups_write_boolean_b)
        subtree:add(f_jgroups_write_boolean, jgroups_write_boolean_range, jgroups_write_boolean)
        offset = offset + 1

        View = require "View"
        offset = View.writeTo(buffer,pinfo,subtree,offset)
    end

    return offset
end


--------------------------------------------------
-- writeStreamable --
--------------------------------------------------
Util.writeStreamable = function(buffer,pinfo,subtree,offset,obj)
    local jgroups_write_boolean_range = buffer(offset,1)
    local jgroups_write_boolean_b = jgroups_write_boolean_range:uint()
    local jgroups_write_boolean = Boolean(jgroups_write_boolean_b)
    subtree:add(f_jgroups_write_boolean, jgroups_write_boolean_range, jgroups_write_boolean)
    offset = offset + 1

    if jgroups_write_boolean == "True" then
        protocol_data = require "protocols.protocol_data"
        offset = protocol_data[obj](buffer,pinfo,subtree,offset)
    end

    return offset
end


--------------------------------------------------
-- writeString --
--------------------------------------------------
Util.writeString = function(buffer,pinfo,subtree,offset)
    local jgroups_byte_flag_range = buffer(offset,1)
    local jgroups_byte_flag_b = jgroups_byte_flag_range:uint()
    local jgroups_byte_flag   = Boolean(jgroups_byte_flag_b)

    subtree:add(f_jgroups_byte_flag, jgroups_byte_flag_range, jgroups_byte_flag)
    offset = offset + 1

    if bit32.band(jgroups_byte_flag_b) == 1 then

        local jgroups_word_size_range = buffer(offset,2)
        local jgroups_word_size = jgroups_word_size_range:uint()
        subtree:add(f_jgroups_word_size, jgroups_word_size_range, jgroups_word_size)
        offset = offset + 2
        
        if jgroups_word_size > 0 then 
            local jgroups_cluster_name_range = buffer(offset,jgroups_word_size)
            local jgroups_cluster_name = jgroups_cluster_name_range:string()
            subtree:add(f_jgroups_cluster_name, jgroups_cluster_name_range, jgroups_cluster_name)
            offset = offset + jgroups_word_size
        end
    end

    return offset
end


--------------------------------------------------
-- Length_decode --
--------------------------------------------------
function decodeLength(raw_len)
    MASK_a  = 0xff
    MASK_b  = 0xf0

    local len_a=bit32.rshift(bit32.band(raw_len, MASK_a), 4)
    local len_b=bit32.band(raw_len, bit32.bnot(MASK_b))

    return len_a + len_b
end

--------------------------------------------------
-- writeLongSequence --
--------------------------------------------------
Util.writeLongSequence = function(buffer,pinfo,subtree,offset)

    local jgroups_writeLong_needed_bytes_range = buffer(offset,1)
    local jgroups_writeLong_needed_bytes = decodeLength(jgroups_writeLong_needed_bytes_range:uint())
    subtree:add(f_jgroups_writeLong_needed_bytes, jgroups_writeLong_needed_bytes_range, jgroups_writeLong_needed_bytes)
    offset = offset + 1

    if jgroups_writeLong_needed_bytes > 0 then
        local jgroups_writeLong_range = buffer(offset,jgroups_writeLong_needed_bytes)
        local jgroups_writeLong = jgroups_writeLong_range:uint()
        subtree:add(f_jgroups_writeLong, jgroups_writeLong_range, jgroups_writeLong)
        offset = offset + jgroups_writeLong_needed_bytes
    end
    
    return offset
end


--------------------------------------------------
-- writeLong --
--------------------------------------------------
Util.writeLong = function(buffer,pinfo,subtree,offset)

    local jgroups_writeLong_needed_bytes_range = buffer(offset,1)
    local jgroups_writeLong_needed_bytes = jgroups_writeLong_needed_bytes_range:uint()
    subtree:add(f_jgroups_writeLong_needed_bytes, jgroups_writeLong_needed_bytes_range, jgroups_writeLong_needed_bytes)
    offset = offset + 1

    if jgroups_writeLong_needed_bytes > 0 then
        local jgroups_writeLong_range = buffer(offset,jgroups_writeLong_needed_bytes)
        local jgroups_writeLong = jgroups_writeLong_range:uint()
        subtree:add(f_jgroups_writeLong, jgroups_writeLong_range, jgroups_writeLong)
        offset = offset + jgroups_writeLong_needed_bytes
    end
    
    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return Util
