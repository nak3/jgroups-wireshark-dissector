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
local PingData = {}


--------------------------------------------------
-- writeTo --
--------------------------------------------------
PingData.writeTo = function(buffer,pinfo,subtree,offset)
    Util = require "util.Util"

	offset = Util.writeAddress(buffer,pinfo,subtree,offset)
	offset = Util.writeView(buffer,pinfo,subtree,offset)
	offset = Util.writeViewId(buffer,pinfo,subtree,offset)

	-- is_server flag
	local jgroups_is_server_flag_range = buffer(offset,1)
	local jgroups_is_server_flag_b = jgroups_is_server_flag_range:uint()
	local jgroups_is_server_flag = Boolean(jgroups_is_server_flag_b)
	subtree:add(f_jgroups_is_server_flag, jgroups_is_server_flag_range, jgroups_is_server_flag)
	offset = offset + 1

	offset = Util.writeString(buffer,pinfo,subtree,offset)
	offset = Util.writeAddresses(buffer,pinfo,subtree,offset)

	return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return PingData
