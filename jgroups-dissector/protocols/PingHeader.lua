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
local PingHeader = {}


--------------------------------------------------
-- PingHeader_type2string --
--------------------------------------------------
function PingHeader_type2string(ph_type)
	result = ""
	if ph_type == 1 then
		result = result .. "GET_MBRS_REQ"
	elseif ph_type == 2 then
		result = result .. "GET_MBRS_REQ"
	else
		result = result .. "<unknown type>"
	end
	return result
end


--------------------------------------------------
-- writeTo --
--------------------------------------------------
PingHeader.writeTo = function (buffer,pinfo,subtree,offset)
   Util = require "util.Util"

   local jgroups_PingHeader_type_range = buffer(offset,1)
   local jgroups_PingHeader_type = PingHeader_type2string(jgroups_PingHeader_type_range:uint())
   subtree:add(f_jgroups_PingHeader_type, jgroups_PingHeader_type_range, jgroups_PingHeader_type)
   offset = offset + 1

   offset = Util.writeStreamable(buffer,pinfo,subtree,offset,"Ping")
   offset = Util.writeString(buffer,pinfo,subtree,offset)
   offset = Util.writeViewId(buffer,pinfo,subtree,offset)

   return offset
end


--------------------------------------------------
-- @@module table@@ --
--------------------------------------------------
return PingHeader
