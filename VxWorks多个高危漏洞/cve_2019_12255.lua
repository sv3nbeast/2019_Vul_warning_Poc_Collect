--[[
-- Author: Axel Boesenach
--
-- TCP-Options Field parser for Suricata to check for CVE-2019-12255
--
-- Suricata rule keyword
--     luajit:cve_2019_12255.lua;
--
-- Suricata rule
-- alert ip any any -> any any (
--     msg:"EXPLOIT - VxWorks CVE-2019-12255 Integer Underflow Observed";
--     flow:to_server;
--     flags:PUA;
--     dsize:>1500;
--     luajit:cve_2019_12255.lua;
--     threshold:type limit, track by_src, count 1, seconds 3600;
--     classtype:attempted-admin;
--     reference:url,armis.com/urgent11/;
--     metadata:created_at 2019-11-05;
--     metadata:CVE 2019-12255;
--     sid:2;
--     rev:1;
-- )
--
--      The script checks for CVE-2019-12255, the packet that is checked needs to have the PSH, ACK, and URG
--      flags set, and have a payload size that exceeds 1500 bytes. It then checks if the value of the urgent
--      pointer is set to 0, this will cause an integer underflow on vulnerable devices.
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
        -- The exploit is based on underflowing the urgent pointer by setting it to 0.
        -- The flaw causes the length constraint in the recv() of the target to be ignored,
        -- and will copy all of the available data from the TCP window to the user supplied
        -- buffer. The rule checks if the payload exceeds 1500 bytes.
        ]]
        if string.byte(data, 55) == 0 and string.byte(data, 56) == 0 then
            return 1
        end
    end
    return 0
end
