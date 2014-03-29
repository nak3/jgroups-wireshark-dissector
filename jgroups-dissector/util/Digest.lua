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
Digest = {}


--------------------------------------------------
-- writeTo --
--------------------------------------------------
Digest.writeTo = function(buffer,pinfo,subtree,offset)
    Util = require "util.Util"
    local jgroups_messageDigest_size_range = buffer(offset,2)
    local jgroups_messageDigest_size = jgroups_messageDigest_size_range:uint()
    subtree:add(f_jgroups_messageDigest_size, jgroups_messageDigest_size_range, jgroups_messageDigest_size )
    offset = offset + 2

    for i=1,tonumber(jgroups_messageDigest_size) do
        offset = Util.writeAddress(buffer,pinfo,subtree,offset)
    end

    for i=1,tonumber(jgroups_messageDigest_size) do
        offset = Util.writeLongSequence(buffer,pinfo,subtree,offset)
    end

    return offset
end


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return Digest
