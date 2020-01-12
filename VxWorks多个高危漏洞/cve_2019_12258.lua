--[[
-- Author: Axel Boesenach
-- TCP-Options Field parser for Suricata to check for CVE-2019-12258
-- Suricata rule keyword 
--     lua:[!]<scriptfilename>;
-- Dummy rule
-- alert ip any any -> any any (
--     msg:"EXPLOIT - VxWorks CVE-2019-12258 SYN Observed";
--     flow:to_server; 
--     luajit:tcpoptions_parser.lua; 
--     treshold:type limit, track by_src, count 1, seconds 3600;
--     classtype:attempted-admin; 
--     reference:url,www.armis.com/urgent11/;
--     reference:url,github.com/ArmisSecurity/urgent11-detector;
--     metadata:created_at 2019-11-05;
--     metadata:CVE 2019-12258;
--     sid:1; 
--     rev:1;
-- )
--
--     The script checks for CVE-2019-12258, the packets involved are marked with a comment in the PCAP.
--     The first detection is being checked given 2 window scale options, 1 invalid and 1 valid (packet #10)
--     The second time it is the unweaponized DoS variant which holds 1 invalid window scale option (packet #15)
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
        -- The Window Scale option has value 03 to indicate this option is being used, this is on a set 
        -- offset of 57 in the TCP packet. The exploit has to be of value 2 (invalid) for this exploit 
        -- to trigger, this valueis located at offset 58. The values are being checked, returning 1 (match) 
        -- if this is the case.
        ]]
        if string.byte(data, 57) == 3 and string.byte(data, 58) == 2 then
            return 1
        end
    end
    return 0
end
