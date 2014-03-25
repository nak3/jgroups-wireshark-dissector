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
local RequestCorrelator = {}


--------------------------------------------------
-- writeTo --
--------------------------------------------------
RequestCorrelator.writeTo = function(buffer,pinfo,tree,offset)
		Util = require "util.Util"

   		local jgroups_RequestCorrelator_type_range = buffer(offset,1)
		local jgroups_RequestCorrelator_type = jgroups_RequestCorrelator_type_range:uint()
		subtree:add(f_jgroups_RequestCorrelator_type, jgroups_RequestCorrelator_type_range, jgroups_RequestCorrelator_type)
		offset = offset + 1

	    offset = Util.writeLong(buffer,pinfo,tree,offset)

   		local jgroups_rsp_expected_flag_range = buffer(offset,1)
		local jgroups_rsp_expected_flag = Boolean(jgroups_rsp_expected_flag_range:uint())
		subtree:add(f_jgroups_rsp_expected_flag, jgroups_rsp_expected_flag_range, jgroups_rsp_expected_flag)
		offset = offset + 1

   		local jgroups_corrId_range = buffer(offset,2)
		local jgroups_corrId = jgroups_corrId_range:uint()
		subtree:add(f_jgroups_corrId, jgroups_corrId_range, jgroups_corrId)
		offset = offset + 2

		return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return RequestCorrelator
