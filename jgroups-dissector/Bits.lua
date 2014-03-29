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
local Bits = {}


--------------------------------------------------
-- writeLong --
--------------------------------------------------
Bits.writeLong = function(buffer,pinfo,subtree,offset)

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
-- writeString --
--------------------------------------------------
Bits.writeString = function(buffer,pinfo,subtree,offset)
    local jgroups_byte_flag_range = buffer(offset,2)
    local jgroups_byte_flag_b = jgroups_byte_flag_range:uint()
    local jgroups_byte_flag   = Boolean(jgroups_byte_flag_b)

    subtree:add(f_jgroups_byte_flag, jgroups_byte_flag_range, jgroups_byte_flag)
    offset = offset + 2

    if bit32.band(jgroups_byte_flag_b) then
        local jgroups_word_size_range = buffer(offset,2)
        local jgroups_word_size = jgroups_word_size_range:uint()
        subtree:add(f_jgroups_word_size, jgroups_word_size_range, jgroups_word_size)
        offset = offset + 2

        local jgroups_cluster_name_range = buffer(offset,jgroups_word_size)
        local jgroups_cluster_name = jgroups_cluster_name_range:string()
        subtree:add(f_jgroups_cluster_name, jgroups_cluster_name_range, jgroups_cluster_name)
        offset = offset + jgroups_word_size
    end
    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return Bits
