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
local FD_SOCK = {}


-- LOCAL FUNCTION --
--------------------------------------------------
-- FD_SOCK_type --
--------------------------------------------------
function FD_SOCK_type(FD_SOCK_type)
    result = ""
    if FD_SOCK_type == 10 then
        result = " SUSPECT"
    elseif FD_SOCK_type == 11 then
        result = "WHO_HAS_SOCK"
    elseif FD_SOCK_type == 12 then
        result = "I_HAVE_SOCK"
    elseif FD_SOCK_type == 13 then
        result = "GET_CACHE"
    elseif FD_SOCK_type == 14 then
        result = "GET_CACHE_RSP"
    end
    return result
end


--------------------------------------------------
-- writeTo --
--------------------------------------------------
FD_SOCK.writeTo = function(buffer,pinfo,subtree,offset)
    Util = require "util.Util"
    local jgroups_FD_SOCK_range = buffer(offset,1)
    local jgroups_FD_SOCK = FD_SOCK_type(jgroups_FD_SOCK_range:uint())
    subtree:add(f_jgroups_FD_SOCK, jgroups_FD_SOCK_range, jgroups_FD_SOCK)
    offset = offset + 1

    offset = Util.writeAddress(buffer,pinfo,subtree,offset)
    offset = Util.writeStreamable(buffer,pinfo,subtree,offset,"IpAddress")
    
    local jgroups_cachedAddrs_size_range = buffer(offset,4)
    local jgroups_cachedAddrs_size = jgroups_cachedAddrs_size_range:uint()
    subtree:add(f_jgroups_cachedAddrs_size, jgroups_cachedAddrs_size_range, jgroups_cachedAddrs_size)
    offset = offset + 4

    for i=1,tonumber(jgroups_cachedAddrs_size) do
        offset = Util.writeAddress(buffer,pinfo,subtree,offset)
        offset = Util.writeStreamable(buffer,pinfo,subtree,offset,"IpAddress")          
    end

    local jgroups_mbrs_size_range = buffer(offset,4)
    local jgroups_mbrs_size = jgroups_mbrs_size_range:uint()
    subtree:add(f_jgroups_mbrs_size, jgroups_mbrs_size_range, jgroups_mbrs_size)
    offset = offset + 4
    for i=1,tonumber(jgroups_mbrs_size) do
        offset = Util.writeAddress(buffer,pinfo,subtree,offset)
    end

    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return FD_SOCK
