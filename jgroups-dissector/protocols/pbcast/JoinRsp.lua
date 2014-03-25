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
JoinRsp = {}


--------------------------------------------------
-- JoinRspTypeFlag --
--------------------------------------------------
function JoinRspTypeFlag(b_JoinRspType)
	--  b_JoinRspType = toBits(d_JoinRspType,3)
	result = ""
	if bit32.band(b_JoinRspType[3]) == 1 then
		result = result .. "FAIL_REASON_PRESENT"
	end
	if bit32.band(b_JoinRspType[2]) == 1 then
		result = result ..  " DIGEST_PRESENT"
	end
	if bit32.band(b_JoinRspType[1]) == 1 then
		result = result .. " VIEW_PRESENT"
	end
	return result
end



--------------------------------------------------
-- writeTo --
--------------------------------------------------
JoinRsp.writeTo = function(buffer,pinfo,tree,offset)
	Util = require "util.Util"
	local jgroups_JoinRsp_Type_range = buffer(offset,1)
	b_JoinRspType = toBits(jgroups_JoinRsp_Type_range:uint(),3)
	local jgroups_JoinRsp_Type = JoinRspTypeFlag(b_JoinRspType)
	subtree:add(f_jgroups_JoinRsp_Type, jgroups_JoinRsp_Type_range, jgroups_JoinRsp_Type)
	offset = offset + 1

	if bit32.band(b_JoinRspType[1]) == 1 then
		-- members size
		ViewId = require "ViewId"
		offset = ViewId.writeTo(buffer,pinfo,tree,offset)
		jgroups_member_size_range = buffer(offset,2)
		jgroups_member_size = jgroups_member_size_range:uint()
		subtree:add(f_jgroups_member_size, jgroups_member_size_range, jgroups_member_size)
		offset = offset + 2
		-- for members writeAddress
		for i=1,tonumber(jgroups_member_size) do
            offset = Util.writeAddress(buffer,pinfo,tree,offset)
		end
	end

	if bit32.band(b_JoinRspType[2]) == 1 and
		bit32.band(b_JoinRspType[1]) == 1
	then
		for i=1,tonumber(jgroups_member_size) do
            offset = Util.writeLongSequence(buffer,pinfo,tree,offset)
		end
	end

	if bit32.band(b_JoinRspType[3]) == 1 then
        local jgroups_fail_reason_size_range = buffer(offset,2)
        local jgroups_fail_reason_size = jgroups_fail_reason_size_range:uint()
        subtree:add(f_jgroups_fail_reason_size, jgroups_fail_reason_size_range, jgroups_fail_reason_size)
        offset = offset + 2

        local jgroups_fail_reason_range = buffer(offset,jgroups_fail_reason_size)
        local jgroups_fail_reason = jgroups_fail_reason_range:string()
        subtree:add(f_jgroups_fail_reason, jgroups_fail_reason_range, jgroups_fail_reason)
        offset = offset + jgroups_fail_reason_size

	end
	
	return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return JoinRsp
