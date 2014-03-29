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
local GMS = {}


-- LOCAL --
--------------------------------------------------
-- GMStype2String --
--------------------------------------------------
function GMStype2String(GMS_type)
   result = ""
   if GMS_type == 1 then
	  result = "JOIN_REQ"
   elseif GMS_type == 2 then
	  result = "JOIN_RSP"
   elseif GMS_type == 3 then
	  result = "LEAVE_REQ"
   elseif GMS_type == 4 then
	  result = "LEAVE_RSP"
   elseif GMS_type == 5 then
	  result = "VIEW"
   elseif GMS_type == 6 then
	  result = "MERGE_REQ"
   elseif GMS_type == 7 then
	  result = "MERGE_RSP"
   elseif GMS_type == 8 then
	  result = "INSTALL_MERGE_VIEW"
   elseif GMS_type == 9 then
	  result = "CANCEL_MERGE"
   elseif GMS_type == 10 then
	  result = "VIEW_ACK"
   elseif GMS_type == 11 then
	  result = "JOIN_REQ_WITH_STATE_TRANSFER"
   elseif GMS_type == 12 then
	  result = "INSTALL_MERGE_VIEW_OK"
   elseif GMS_type == 13 then
	  result = "GET_DIGEST_REQ"
   elseif GMS_type == 14 then
	  result = "GET_DIGEST_RSP"
   elseif GMS_type == 15 then
	  result = "INSTALL_DIGEST"
   else
	  result = "unknown"
   end
   return result
end


--------------------------------------------------
-- writeTo --
--------------------------------------------------
GMS.writeTo = function(buffer,pinfo,subtree,offset)
		Util = require "util.Util"
		
		local jgroups_GMS_type_range = buffer(offset,1)
		local jgroups_GMS_type = GMStype2String(jgroups_GMS_type_range:uint())
		subtree:add(f_jgroups_GMS_type, jgroups_GMS_type_range, jgroups_GMS_type)
		offset = offset + 1
		
   		local jgroups_isMergeViewFlag_range = buffer(offset,1)
		local jgroups_isMergeViewFlag = Boolean(jgroups_isMergeViewFlag_range:uint())
		subtree:add(f_jgroups_isMergeViewFlag, jgroups_isMergeViewFlag_range, jgroups_isMergeViewFlag)
		offset = offset + 1

		offset = Util.writeStreamable(buffer,pinfo,subtree,offset,"View")

		offset = Util.writeAddress(buffer,pinfo,subtree,offset)
		offset = Util.writeAddresses(buffer,pinfo,subtree,offset)
		
		offset = Util.writeStreamable(buffer,pinfo,subtree,offset,"JoinRsp")
		offset = Util.writeStreamable(buffer,pinfo,subtree,offset,"Digest")
		offset = Util.writeStreamable(buffer,pinfo,subtree,offset,"MergeId")

   		local jgroups_merge_rejected_flag_range = buffer(offset,1)
		local jgroups_merge_rejected_flag = Boolean(jgroups_merge_rejected_flag_range:uint())
		subtree:add(f_jgroups_merge_rejected_flag, jgroups_merge_rejected_flag_range, jgroups_merge_rejected_flag)
		offset = offset + 1

   		local jgroups_useFlashIfPresent_flag_range = buffer(offset,1)
		local jgroups_useFlashIfPresent_flag = Boolean(jgroups_useFlashIfPresent_flag_range:uint())
		subtree:add(f_jgroups_useFlashIfPresent_flag, jgroups_useFlashIfPresent_flag_range, jgroups_useFlashIfPresent_flag)
		offset = offset + 1

		return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return GMS
