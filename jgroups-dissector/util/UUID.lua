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
local UUID = {}


--------------------------------------------------
-- writeTo --
--------------------------------------------------
UUID.writeTo = function(buffer,pinfo,subtree,offset)
    -- ** jgroups least significant bits ** --
    local jgroups_least_sig_bits_range = buffer(offset,8)
    local jgroups_least_sig_bits = jgroups_least_sig_bits_range:uint64()
    subtree:add(f_jgroups_least_sig_bits, jgroups_least_sig_bits_range, jgroups_least_sig_bits)
    offset = offset + 8

    -- ** jgroups most significant bits ** --
    local jgroups_most_sig_bits_range = buffer(offset,8)
    local jgroups_most_sig_bits = jgroups_most_sig_bits_range:uint64()
    subtree:add(f_jgroups_most_sig_bits, jgroups_most_sig_bits_range, jgroups_most_sig_bits)
    offset = offset + 8

    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return UUID
