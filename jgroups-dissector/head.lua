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
-- header_id --
--------------------------------------------------
function header_id(id_num)

    protocol_id = require "protocol_id"
	-- workaround
	if id_num == 200 then
		return "RequestCorrelator"
	elseif id_num == 201 then
		return "MuxRequestCorrelator"
	elseif id_num == 202 then
		return "MPerf"
	end

	return protocol_id[id_num]
end


--------------------------------------------------
-- toBits --
--------------------------------------------------
function toBits(num,digit)
	-- returns a table of bits, least significant first.
	local t={} -- will contain the bits
	while digit>0 do
		rest=math.fmod(num,2)
		t[#t+1]=rest
		num=(num-rest)/2
		digit=digit-1
	end
	return t
end


--------------------------------------------------
-- Boolean --
--------------------------------------------------
function Boolean(d_data)
	b_data = toBits(d_data,1)
	if b_data[1] == 1 then
		return "True"
	else
		return "False"
	end
end


--------------------------------------------------
-- version_decode --
--------------------------------------------------
function version_decode(raw_version)
	MAJOR_SHIFT = 11
	MINOR_SHIFT = 6
	MAJOR_MASK  = 0x00f800
	MINOR_MASK  = 0x0007c0
	MICRO_MASK  = 0x00003f

	major=bit32.rshift(bit32.band(raw_version, MAJOR_MASK), MAJOR_SHIFT)
	minor=bit32.rshift(bit32.band(raw_version, MINOR_MASK), MINOR_SHIFT)
	micro=bit32.band(raw_version, MICRO_MASK)
	
	return major .. "." .. minor .. "." .. micro
end


--------------------------------------------------
-- mcastFlag --
--------------------------------------------------
function mcastFlag(d_mcastFlag)
	b_mcastFlag = toBits(d_mcastFlag,3)
	result = ""
	if bit32.band(b_mcastFlag[3]) == 1 then
		result = result .. "LIST" -- we have a list of messages rather than a single message when set
	end
	if bit32.band(b_mcastFlag[2]) == 1 then
		result = result .. " MULTICAST" -- message is a multicast (versus a unicast) message when set
	end
	if bit32.band(b_mcastFlag[1]) == 1 then
		result = result .. " OOB" -- message has OOB flag set (Message.OOB)
	end
	return result
end

--------------------------------------------------
-- leading --
--------------------------------------------------
function leading(b_leading)
	result = ""
	if bit32.band(b_leading[1]) == 1 then
		result = result .. "DEST_ADDR"
	end
	if bit32.band(b_leading[2]) == 1 then
		result = result .. " SRC_ADDR"
	end
	if bit32.band(b_leading[3]) == 1 then
		result = result .. " BUF_SET"
	end
	return result
end


--------------------------------------------------
-- msgTypeFlag --
--------------------------------------------------
function msgTypeFlag(d_msgType)
	b_msgType = toBits(d_msgType,8)
	result = ""
	if bit32.band(b_msgType[8]) == 1 then
		result = result .. " RSVP"
	end
	if bit32.band(b_msgType[7]) == 1 then
		result = result .. " NO_RELAY"
	end
	if bit32.band(b_msgType[6]) == 1 then
		result = result .. " NO_TOTAL_ORDER"
	end
	if bit32.band(b_msgType[5]) == 1 then
		result = result .. " NO_RELIABILITY"
	end
	if bit32.band(b_msgType[4]) == 1 then
		result = result .. " SCOPED"
	end
	if bit32.band(b_msgType[3]) == 1 then
		result = result .. " NO_FC"
	end
	if bit32.band(b_msgType[2]) == 1 then
		result = result .. " DONT_BUNDLE"
	end
	if bit32.band(b_msgType[1]) == 1 then
		result = result .. " OOB"
	end
	return result
end


--------------------------------------------------
-- addressTypeFlag --
--------------------------------------------------
function addressTypeFlag(d_addressType)
	b_addressType = toBits(d_addressType,5)
	if bit32.band(b_addressType[1]) == 1 then
		return "NULL"
	end
	if bit32.band(b_addressType[2]) == 1 then
		return "UUID_ADDR"
	end
	if bit32.band(b_addressType[3]) == 1 then
		return "SITE_UUID"
	end
	if bit32.band(b_addressType[4]) == 1 then
		return "SITE_MASTER"
	end
	if bit32.band(b_addressType[5]) == 1 then
		return "IP_ADDR"
	end
end


