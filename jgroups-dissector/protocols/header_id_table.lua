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
local header_id_table = {}

PingHeader    = require "PingHeader"
FD_SOCK       = require "FD_SOCK"
FD_ALL        = require "FD_ALL"
TpHeader      = require "TpHeader"
MERGE3        = require "MERGE3"
UNICAST2      = require "UNICAST2"
RSVP          = require "RSVP"
FD            = require "FD"
GMS           = require "pbcast.GMS"
STABLE        = require "pbcast.STABLE"
NakAckHeader  = require "pbcast.NakAckHeader"
RequestCorrelator = require "blocks.RequestCorrelator"


header_id_table["PING"]     = PingHeader.writeTo
header_id_table["MPING"]    = PingHeader.writeTo
header_id_table["FD_SOCK"]  = FD_SOCK.writeTo
header_id_table["FD_ALL"]   = FD_ALL.writeTo
header_id_table["UDP"]      = TpHeader.writeTo
header_id_table["TCP"]      = TpHeader.writeTo
header_id_table["MERGE3"]   = MERGE3.writeTo
header_id_table["UNICAST2"] = UNICAST2.writeTo
header_id_table["RSVP"]     = RSVP.writeTo
header_id_table["FD"]       = FD.writeTo
header_id_table["GMS"]      = GMS.writeTo
header_id_table["STABLE"]   = STABLE.writeTo
header_id_table["NAKACK"]   = NakAckHeader.writeTo
header_id_table["RequestCorrelator"]   = RequestCorrelator.writeTo

--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return header_id_table
