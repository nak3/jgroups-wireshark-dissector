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
TpHeader = {}


--------------------------------------------------
-- writeTo --
--------------------------------------------------
TpHeader.writeTo = function(buffer,pinfo,subtree,offset)
    local jgroups_word_size_range = buffer(offset,2)
    local jgroups_word_size = jgroups_word_size_range:uint()
    subtree:add(f_jgroups_word_size, jgroups_word_size_range, jgroups_word_size)
	offset = offset + 2
	
    local jgroups_cluster_name_range = buffer(offset,jgroups_word_size)
    local jgroups_cluster_name = jgroups_cluster_name_range:string()
    subtree:add(f_jgroups_cluster_name, jgroups_cluster_name_range, jgroups_cluster_name)
	offset = offset + jgroups_word_size

    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return TpHeader
