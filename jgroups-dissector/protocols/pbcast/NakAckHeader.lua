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
local NakAckHeader = {}


-- LOCAL --
--------------------------------------------------
-- NakAckHeaderType2String --
--------------------------------------------------
function NakAckHeaderType2String(NakAckHeader_Type)
    result = ""
    if NakAckHeader_Type == 1 then
        result = "MSG"
    elseif NakAckHeader_Type == 2 then
        result = "XMIT_REQ"
    elseif NakAckHeader_Type == 3 then
        result = "XMIT_RSP"
    else
        result = "<undefined>"
    end
    return result
end


--------------------------------------------------
-- writeTo --
--------------------------------------------------
NakAckHeader.writeTo =  function(buffer,pinfo,tree,offset)
    Util = require "util.Util"
    local jgroups_NakAckHeaderType_Type_range = buffer(offset,1)
    local jgroups_NakAckHeaderType_Type = NakAckHeaderType2String(jgroups_NakAckHeaderType_Type_range:uint())
    subtree:add(f_jgroups_NakAckHeaderType_Type, jgroups_NakAckHeaderType_Type_range, jgroups_NakAckHeaderType_Type)
    offset = offset + 1

    if jgroups_NakAckHeaderType_Type == "MSG" then
        -- nothing to do
    elseif jgroups_NakAckHeaderType_Type == "XMIT_RSP" then
        offset = Util.writeLong(buffer,pinfo,tree,offset)
    elseif jgroups_NakAckHeaderType_Type == "XMIT_REQ" then
        offset = Util.writeStreamable(buffer,pinfo,tree,offset,"Range")
        offset = Util.writeAddress(buffer,pinfo,tree,offset)
    end

    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return NakAckHeader
