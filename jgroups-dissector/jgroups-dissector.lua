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
-- @@Global setting@@ --
--------------------------------------------------
do
    plugin_path = Dir.personal_plugins_path()

    package.prepend_path("protocols")
    package.prepend_path("util")
    package.prepend_path("stack")
    package.prepend_path("blocks")
    dofile(plugin_path .. "/jgroups-dissector/head.lua")
    dofile(plugin_path .. "/jgroups-dissector/jgroups-field.lua")

    local jgroups_proto = Proto("jgroups_proto", "JGroups packet")

    jgroups_proto.fields = {
        f_jgroups_byte_flag,

        --** writeMessage **--
        f_jgroups_version,                 -- 2byte: JGroups Version
        f_jgroups_mcast_flag,               -- 1byte:

        -- msg.writeTo
        f_jgroups_leading,                 -- 1byte:
        f_jgroups_msg_type_flag,             -- 2byte:

        -- writeAddress
        f_jgroups_address_type_flag,         -- 1byte:

        -- addr.writeTo
        f_jgroups_least_sig_bits,            -- 8byte:
        f_jgroups_most_sig_bits,             -- 8byte:

        f_jgroups_buffer_size,             -- 4byte
        f_jgroups_buffer,                  -- $(jgroups_buffer_size) byte
        -- headers.size
        f_jgroups_headers_size,             -- 2byte:

        f_jgroups_header_id,                -- 2byte:
        f_jgroups_header_magic_number,       -- 2byte:

        -- header.writeTo
        f_jgroups_word_size,
        f_jgroups_cluster_name,

        -- PingData
        f_jgroups_is_server_flag,       -- 1byte
        
        f_jgroups_PingHeader_type,    --1byte
        f_jgroups_write_boolean,

        -- bits / util.writeLong
        f_jgroups_writeLong_needed_bytes,
        f_jgroups_writeLong,
        f_jgroups_pbcastStable_type,

        f_jgroups_messageDigest_size,
        f_jgroups_MERGE3_type,
        f_jgroups_member_size,

        f_jgroups_IpAddress_size, --1byte
        f_jgroups_IpAddress,     --4byte (ipv4)
        f_jgroups_port,           --2byte

        --UNICAST2
        f_jgroups_Unicast2_type,
        f_jgroups_conn_id, --1byte
        f_jgroups_flag_as_first,   --1byte

        -- FD_SOCK
        f_jgroups_FD_SOCK_type,
        f_jgroups_cachedAddrs_size,
        f_jgroups_mbrs_size,

        -- RSVP
        f_jgroups_RSVP_type,
        f_jgroups_RSVP_Id,

        -- GMS
        f_jgroups_GMS_type,
        f_jgroups_merge_rejected_flag,
        f_jgroups_useFlashIfPresent_flag,

        -- FD
        f_jgroups_FD_type,

        -- Merge ID
        f_jgroups_merge_id,

        -- RequestCorrelator
        f_jgroups_RequestCorrelator_type,
        f_jgroups_rsp_expected_flag,
        f_jgroups_corrId,

        -- SiteUUID
        f_jgroups_site,

        -- JoinRsp
        f_jgroups_fail_reason_size,
        f_jgroups_fail_reason
    }


    --------------------------------------------------
    -- jgroups_proto.dissector --
    --------------------------------------------------
    function jgroups_proto.dissector(buffer,pinfo,tree)

        local offset = 0
        subtree = tree:add(jgroups_proto, buffer(), "JGroups packet data")

        if version_decode(buffer:range(4,2):uint()) == "3.2.12" then
            -- first cookie
            if buffer:range(0,4):string() == "bela" then
                offset = offset + 4
                local TCPConnectionMap = require "blocks.TCPConnectionMap"
                TCPConnectionMap.sendLocalAddress(buffer,pinfo,subtree,offset)
                return
            end
            p = "tcp"
        elseif version_decode(buffer:range(0,2):uint()) == "3.2.12" then
            p = "udp"
        end
        -- ** add protocol tree ** --
        local Message = require "Message"
        Message.writeTo(buffer,pinfo,subtree,offset,p)

    end

    --------------------------------------------------
    -- heur_dissect_jgroups --
    --------------------------------------------------
    local function heur_dissect_jgroups(buffer,pinfo,tree)
        supported_version = require "supported_version"
        if buffer:len() < 8 then
            return false
        end
        if supported_version[version_decode(buffer:range(0,2):uint())]
            or supported_version[version_decode(buffer:range(4,2):uint())]
        then
            jgroups_proto.dissector(buffer,pinfo,tree)
            pinfo.conversation = jgroups_proto
            return true
        end
        return false
    end

    --   If you don't want to use heuristic, use it.
    --   DissectorTable.get("udp.port"):add(45688, jgroups_proto)
    --   DissectorTable.get("tcp.port"):add(42081, jgroups_proto)
    jgroups_proto:register_heuristic("udp",heur_dissect_jgroups)
    jgroups_proto:register_heuristic("tcp",heur_dissect_jgroups)
end
