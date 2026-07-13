"""Compatibility fix for python-iptables with iptables >= 1.8.11.

iptables 1.8.11 added the 'base' member to struct xt_option_entry, growing the struct
from 48 to 56 bytes on 64-bit platforms. python-iptables (as of 1.2.0) still uses the
old layout, so walking an extension's option table reads all entries after the first
one at wrong offsets. Option lookups then fail with errors such as
XTablesError: b'udp': no such parameter b'dport'.

Only the array stride is affected: struct xtables_match, struct xtables_target and
struct xt_option_call are unchanged, and option entries are always passed on by
reference. It is therefore sufficient to reiterate the option table with the correct
stride whenever python-iptables looks up an option by name.
"""
import ctypes as ct

import iptc.xtables


class _XTOptionEntry1811(ct.Structure):
    # struct xt_option_entry with the 'base' member introduced in iptables 1.8.11
    _fields_ = iptc.xtables.xt_option_entry._fields_ + [('base', ct.c_uint)]


def _has_1811_option_layout():
    xt = iptc.xtables.xtables(iptc.xtables.NFPROTO_IPV4)
    match = xt.find_match(b'udp')
    if not match:
        return False
    options = match[0].x6_options
    if not options or options[0].name != b'source-port':
        return False
    # The udp match registers 'sport' as its second option. When the extension is built
    # against iptables >= 1.8.11, reading the table with the old stride terminates it
    # after the first entry, while the new stride yields the expected option name.
    return not options[1].name and \
        ct.cast(options, ct.POINTER(_XTOptionEntry1811))[1].name == b'sport'


def patch():
    if getattr(iptc.xtables.xtables, '_option_lookup_1811', False):
        return
    if not _has_1811_option_layout():
        return

    def _option_lookup(self, entries, name):
        for entry in ct.cast(entries, ct.POINTER(_XTOptionEntry1811)):
            if not entry.name:
                break
            if entry.name == name:
                # Return a view of the entry with the type the callers expect. The
                # underlying memory keeps the real layout, which is what libxtables
                # and the extensions read.
                return ct.cast(ct.pointer(entry),
                               ct.POINTER(iptc.xtables.xt_option_entry))[0]
        return None

    iptc.xtables.xtables._option_lookup = _option_lookup
    iptc.xtables.xtables._option_lookup_1811 = True
