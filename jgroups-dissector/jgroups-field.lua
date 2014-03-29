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
-- @@JGroups pro@@ --
--------------------------------------------------

f_jgroups_byte_flag                =     ProtoField.string ("jgroups_proto.byteFlag"             ,   "flag"             )
f_jgroups_version                  =     ProtoField.string ("jgroups_proto.version"              ,   "version"             )
f_jgroups_mcast_flag               =     ProtoField.string ("jgroups_proto.mcast_flag"           ,   "mcast flags"         )
f_jgroups_leading                  =     ProtoField.string ("jgroups_proto.leading"              ,   "leading"             )
f_jgroups_msg_type_flag            =     ProtoField.string ("jgroups_proto.msgType_flag"         ,   "message type flags"  )

f_jgroups_address_type_flag        =     ProtoField.string  ("jgroups_proto.address_type_flag"   ,   "address type flags"  )
f_jgroups_least_sig_bits           =     ProtoField.uint64 ("jgroups_proto.least_sig_bits"       ,   "LeastSigBits"        )
f_jgroups_most_sig_bits            =     ProtoField.uint64 ("jgroups_proto.most_sig_bits"        ,   "MostSigBits"         )

f_jgroups_buffer_size              =     ProtoField.int16 ("jgroups_proto.buffer_size"           ,   "buffer_size"         )
f_jgroups_buffer                   =     ProtoField.string ("jgroups_proto.buffer"               ,   "buffer"         )

f_jgroups_headers_size             =     ProtoField.int16  ("jgroups_proto.headers_size"         ,   "headers size"        )
f_jgroups_header_id                =     ProtoField.string ("jgroups_proto.header_id"            ,   "header ID"           )
f_jgroups_header_magic_number      =     ProtoField.int16  ("jgroups_proto.header_magic_number"  ,   "header magic_number" )
f_jgroups_word_size                =     ProtoField.int16  ("jgroups_proto.word_size"            ,   "word Size"           )
f_jgroups_cluster_name             =     ProtoField.string ("jgroups_proto.cluster_name"         ,   "cluster name"        )
f_jgroups_PingHeader_type          =     ProtoField.string  ("jgroups_proto.PingHeader_type"     ,   "ping type"           )
f_jgroups_is_server_flag           =     ProtoField.string ("jgroups_proto.is_server_flag"       ,    "ping data is_server flag"   )


f_jgroups_write_boolean            =     ProtoField.string ("jgroups_proto.write_boolean"        ,    "write boolean"   )
f_jgroups_writeLong_needed_bytes   =     ProtoField.string ("jgroups_proto.writeLong_needed_bytes",    "write long needed bytes"   )
f_jgroups_writeLong                =     ProtoField.string ("jgroups_proto.writeLong"            ,    "write long"   )

f_jgroups_pbcastStable_type        =     ProtoField.string ("jgroups_proto.pbcastStable_type"    ,    "pbcast stable type"   )
f_jgroups_messageDigest_size       =     ProtoField.string ("jgroups_proto.messageDigest_size"   ,    "message Digest Size"   )

f_jgroups_MERGE3_type              =     ProtoField.string ("jgroups_proto.MERGE3_type"          ,    "MERGE3 type"      )
f_jgroups_member_size              =     ProtoField.int16  ("jgroups_proto.member_size"          ,   "member size"         )

-- IpAddress.lua
f_jgroups_IpAddress_size           =     ProtoField.int16  ("jgroups_proto.IpAddress_size"       ,   "IP Address Size"             )
f_jgroups_IpAddress                =     ProtoField.string  ("jgroups_proto.IpAddress"           ,   "IP Address"              )
f_jgroups_port                     =     ProtoField.int16  ("jgroups_proto.port"                 ,   "Port Number"             )

-- UNICAST2.lua
f_jgroups_Unicast2_type            =     ProtoField.string  ("jgroups_proto.UNICAST2Type"        ,   "UNICAST2 type"           )
f_jgroups_conn_id                  =     ProtoField.int16  ("jgroups_proto.conn_id"              ,   "connection id"           )
f_jgroups_flag_as_first            =     ProtoField.string  ("jgroups_proto.flag_as_first"       ,   "flag_as_first flag"            )

f_jgroups_RSVP_type                =     ProtoField.string  ("jgroups_proto.RSVP_type"           ,   "RSVP Type"           )
f_jgroups_RSVP_Id                  =     ProtoField.int16  ("jgroups_proto.RSVP_Id"              ,   "RSVP ID"             )

-- FD_SOCK
f_jgroups_FD_SOCK_type             =     ProtoField.string  ("jgroups_proto.FD_SOCK_type"        ,   "FD_SOCK Type"            )
f_jgroups_cachedAddrs_size         =     ProtoField.int16  ("jgroups_proto.cachedAddrs_size"     ,   "cachedAddrs Size"            )
f_jgroups_mbrs_size                =     ProtoField.int16  ("jgroups_proto.mbrs_size"            ,   "mbrs Size"           )

-- GMS
f_jgroups_GMS_type                 =     ProtoField.string  ("jgroups_proto.GMS_type"            ,   "GMS_type flag"           )
f_jgroups_merge_rejected_flag      =     ProtoField.string  ("jgroups_proto.merge_rejected_flag" ,   "merge_rejected_flag flag"             )
f_jgroups_useFlashIfPresent_flag   =     ProtoField.string  ("jgroups_proto.useFlashIfPresent_flag",   "useFlashIfPresent_flag flag"              )

f_jgroups_FD_type                  =     ProtoField.string  ("jgroups_proto.FD_type"             ,   "FD_type flag"            )
f_jgroups_merge_id                 =     ProtoField.int16  ("jgroups_proto.jgroups_merge_id"     ,   "Merge ID"            )

-- RequestCorrelator
f_jgroups_RequestCorrelator_type   =     ProtoField.int16  ("jgroups_proto.jgroups_RequestCorrelator_type"              ,   "RequestCorrelator_type")
f_jgroups_rsp_expected_flag        =     ProtoField.string  ("jgroups_proto.jgroups_rsp_expected_flag"              ,   "Response Expected Flag")
f_jgroups_corrId                   =     ProtoField.int16  ("jgroups_proto.jgroups_corrId"       ,   "Corrlator ID")

-- SitUUID
f_jgroups_site                     =     ProtoField.int16  ("jgroups_proto.jgroups_site"         ,   "SiteUUID site")

-- JoinRsp
f_jgroups_fail_reason_size         =     ProtoField.int16  ("jgroups_proto.jgroups_fail_reason_size"  ,   "fail_reason size")
f_jgroups_fail_reason              =     ProtoField.string  ("jgroups_proto.jgroups_fail_reason"      ,   "fail_reason size")
