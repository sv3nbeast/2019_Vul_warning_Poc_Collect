--[[
-- Author: Axel Boesenach
--
-- IP-Options Field parser for Suricata to check for CVE-2019-12256 LSRR Options
--
-- Suricata rule keyword
--     luajit:cve_2019_12256_lsrr.lua;
--
-- Suricata rule
-- alert ip any any -> any any (
--     msg:"EXPLOIT - VxWorks CVE-2019-12256 Double Invalid LSRR Options Observed";
--     flow:to_server;
--     luajit:cve_2019_12256_lsrr.lua;
--     threshold:type limit, track by_src, count 1, seconds 3600;
--     classtype:attempted-admin;
--     reference:url,armis.com/urgent11/;
--     metadata:created_at 2019-11-12;
--     metadata:cve,2019-12256;
--     sid:4;
--     rev:1;
-- )
--
--     The script checks for CVE-2019-12256, the packet that is checked consists of two LSRR options in the IP packet.
--     The LSRR options can be recognized with hex value 0x83, the exploit gives it invalid values, the length is less
--     than the length normally used when defining a route (4 bytes minimum), this is present twice in the packet that
--     is sent to the server. The following IP options will trigger a stack overflow:
--
--     Type LSRR        Length          LSRR-Pointer    Type LSRR       Length          LSRR-Pointer
--     \x83             \x03            \x27            \x83            \x03            \x27
]]

-- Initialize the script
function init (args)
    local needs = {}
    needs["packet"] = tostring(true)
    return needs
end

-- Try and match the condition
function match (args)
    --[[
    -- The exploit is based on the LSRR having a length of less than 4 bytes and being present twice in the packet
    -- Furthermore, the LSRR pointer is pointing past the end of the option (\x27)
    ]]
    for index, data in pairs(args) do
        if(string.byte(data, 63) == 131 and string.byte(data, 64) < 4 and string.byte(data, 65) == 39
            and string.byte(data, 66) == 131 and string.byte(data, 67) < 4 and string.byte(data, 68) == 39) then
            return 1
        end
    end
    return 0
end
