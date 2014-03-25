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
local protocol_id = {}

protocol_id =
{
nil                     , --    1
"FD"                    , --    2
"FD_SOCK"               , --    3
"FRAG"                  , --    4
"FRAG2"                 , --    5
"PING"                  , --    6
"MPING"                 , --    7
"S3_PING"               , --    8
"FILE_PING"             , --    9
"TCPPING"               , --    10
"TCPGOSSIP"             , --    11
"UNICAST"               , --    12
"VERIFY_SUSPECT"        , --    13
"GMS"                   , --    14
"NAKACK"                , --    15
"STABLE"                , --    16
"STATE_TRANSFER"        , --    17
nil                     , --    18
"COMPRESS"              , --    19
"FC"                    , --    20
"UDP"                   , --    21
"TCP"                   , --    22
"TCP_NIO"               , --    23
"TUNNEL"                , --    24
"ENCRYPT"               , --    25
"SEQUENCER"             , --    26
"FD_SIMPLE"             , --    27
"FD_ICMP"               , --    28
"FD_ALL"                , --    29
nil                     , --    30
"FLUSH"                 , --    31
nil                     , --    32
"AUTH"                  , --    33
"STATE"                 , --    34
"STATE_SOCK"            , --    35
"HTOTAL"                , --    36
"DISCARD"               , --    37
nil                     , --    38
"SHARED_LOOPBACK"       , --    39
"UNICAST2"              , --    40
"SCOPE"                 , --    41
"DAISYCHAIN"            , --    42
"RELAY"                 , --    43
"MFC"                   , --    44
"UFC"                   , --    45
"JDBC_PING"             , --    46
"STOMP"                 , --    47
"PRIO"                  , --    48
"BPING"                 , --    49
"CENTRAL_LOCK"          , --    50
"PEER_LOCK"             , --    51
"CENTRAL_EXECUTOR"      , --    52
"COUNTER"               , --    53
"MERGE3"                , --    54
"RSVP"                  , --    55
"RACKSPACE_PING"        , --    56
"NAKACK2"               , --    57
"tom_TOA"               , --    58
"SWIFT_PING"            , --    59
"relay_RELAY2"          , --    60
"FORWARD_TO_COORD"        --    61

-- "RequestCorrelator"     , --    200
-- "MuxRequestCorrelator"  , --    201
-- "MPerf"                   --    202
}

--------------------------------------------------
-- @@return@@ --
--------------------------------------------------
return protocol_id
