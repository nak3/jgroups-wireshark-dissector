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
local IpAddress = {}


--------------------------------------------------
-- writeTo --
--------------------------------------------------
IpAddress.writeTo = function (buffer,pinfo,tree,offset)
    local jgroups_IpAddress_size_range = buffer(offset,1)
    local jgroups_IpAddress_size = jgroups_IpAddress_size_range:uint()
    subtree:add(f_jgroups_IpAddress_size, jgroups_IpAddress_size_range, jgroups_IpAddress_size)
    offset = offset + 1

	-- TODO hex
    local jgroups_IpAddress_range = buffer(offset,4)
    local jgroups_IpAddress = buffer(offset,1):uint()
    local tmp_point = 1
    for i=2,tonumber(jgroups_IpAddress_size) do
        IpAddress_range = buffer(offset+tmp_point,1)
        jgroups_IpAddress = jgroups_IpAddress .. "." .. IpAddress_range:uint()
        tmp_point = tmp_point + 1
    end
    subtree:add(f_jgroups_IpAddress, jgroups_IpAddress_range, jgroups_IpAddress)
    offset = offset + jgroups_IpAddress_size

    -- Port
    local jgroups_port_range = buffer(offset, 2)
    local jgroups_port = jgroups_port_range:uint()
    subtree:add(f_jgroups_port, jgroups_port_range, jgroups_port)
    offset = offset + 2

    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return IpAddress
