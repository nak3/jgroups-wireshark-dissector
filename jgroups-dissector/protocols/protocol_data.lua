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
local protocol_data = {}


View      = require "View"
IpAddress = require "stack.IpAddress"
JoinRsp   = require "protocols.pbcast.JoinRsp"
Digest    = require "util.Digest"
PingData  = require "protocols.PingData"
Range     = require "util.Range"
MergeId   = require "util.MergeId"


protocol_data["Ping"]      = PingData.writeTo
protocol_data["Digest"]    = Digest.writeTo
protocol_data["Range"]     = Range.writeTo
protocol_data["View"]      = View.writeTo
protocol_data["JoinRsp"]   = JoinRsp.writeTo
protocol_data["MergeId"]   = MergeId.writeTo
protocol_data["IpAddress"] = IpAddress.writeTo


--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return protocol_data
