--[[
-- Author: Axel Boesenach
--
-- TCP-Options Field parser for Suricata to check for CVE-2019-12260
--
-- Suricata rule keyword
--     luajit:cve_2019_12260.lua;
--
-- Suricata rule
-- alert ip any any -> any any (
--     msg:"EXPLOIT - VxWorks CVE-2019-12260 Malformed TCP-AO Detected";
--     flow:to_server;
--     flags:S;
--     luajit:cve_2019_12260.lua;
--     threshold:type limit, track by_src, count 1, seconds 3600;
--     classtype:attempted-admin;
--     reference:url,armis.com/urgent11/;
--     metadata:created_at 2019-11-06;
--     metadata:CVE 2019-12260;
--     sid:3;
--     rev:1;
-- )
--
--     The script checks for CVE-2019-12260, the packet that is checked consists of a malformed SYN packet,
--     this packet contains a TCP-AO option field with a byte value of <= 3 bytes. The TCP-AO option can be
--     set with hex value 0x29, as per RFC: https://tools.ietf.org/html/rfc5925#page-7
]]

-- Initialize the script
function init (args)
    local needs = {}
    needs["packet"] = tostring(true)
    return needs
end

-- Try and match the condition
function match (args)
    for index, data in pairs(args) do
        --[[
        -- The exploit is based on malforming the TCP-AO option by setting it to anything that is less than
        -- or equal to 3 bytes. This can be checked by verifying that hex value 0x29 is set as an option at
        -- offset 56
        ]]
        if string.byte(data, 57) == 29 and string.byte(data, 58) < 4 then
            return 1
        end
    end
    return 0
end
