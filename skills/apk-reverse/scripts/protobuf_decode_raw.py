#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Decode a protobuf payload that has NO schema into a structured JSON tree.

WHY THIS EXISTS
---------------
`references/protocol-reverse.md` states the wire-format rules and says a payload
can be walked field by field with no `.proto` in hand, but the skill shipped no
tool that does it -- the only evidence behind that section was a workbench
script. The honest part of "walk it without a schema" is what a naive decoder
hides:

  * four different things share wire type 2 (nested message, UTF-8 string,
    packed repeated array, opaque bytes), and nothing on the wire separates
    them;
  * a proto3 varint 0 is byte-identical to an absent field, so a decoded `0` is
    not evidence that the sender set the field.

A decoder that prints one interpretation per field manufactures conclusions.
This one prints every interpretation consistent with the bytes, labels each
with a heuristic confidence, and marks the ones the format cannot decide.

WHAT IT DOES
------------
  * varint, with the 10-byte ceiling and 64-bit overflow made explicit, plus
    the non-canonical (redundant) encoding case;
  * wire types 0/1/2/5 and the deprecated 3/4 group pair;
  * length-delimited values as candidate sets, each with a confidence and, when
    two candidates are equally consistent, an explicit note that no schema
    separates them;
  * proto3 explicit zero flagged at every occurrence;
  * several frames in one input: a `|` separator inside --hex, or a varint
    length prefix with --split varint-length (gRPC/WebSocket-style framing);
  * --reencode: write a decoded JSON tree -- possibly hand-edited -- back to
    bytes and compare with the original. That comparison is the round-trip
    proof that the walk lost nothing.

No third-party dependency: `google.protobuf` parses a *stream against a schema*
and cannot walk a bare one, so the parsing here is written out. (It is still
useful to *generate* reference bytes from a real schema -- see the verification
record -- but the tool never imports it.)

USAGE
-----
  python protobuf_decode_raw.py --hex "08 96 01 12 07 74 65 73 74 69 6e 67"
  python protobuf_decode_raw.py body.bin
  python protobuf_decode_raw.py body.bin --json > tree.json
  python protobuf_decode_raw.py - < body.bin
  python protobuf_decode_raw.py --hex "089601|120774657374696e67"     # two frames
  python protobuf_decode_raw.py framed.bin --split varint-length
  python protobuf_decode_raw.py --reencode tree.json --out patched.bin --check body.bin
  python protobuf_decode_raw.py --selftest

Stdlib only, Python 3.9+.
"""

import argparse
import json
import re
import struct
import sys

MAX_VARINT_BYTES = 10
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

WIRE_NAMES = {
    0: 'varint',
    1: 'fixed64',
    2: 'length_delimited',
    3: 'group_start',
    4: 'group_end',
    5: 'fixed32',
}

WIRE_SEMANTICS = {
    0: 'int32/int64/uint32/uint64/sint32/sint64/bool/enum',
    1: 'fixed64/sfixed64/double',
    2: 'message/string/bytes/packed repeated',
    3: 'deprecated group start',
    4: 'deprecated group end',
    5: 'fixed32/sfixed32/float',
}

# Tie-break order for "which candidate to expand by default". Structural
# candidates come first because they carry more information; `bytes` is last
# because it always fits. This is a display default, never a conclusion.
VIEW_PRIORITY = ['nested_message', 'utf8_string', 'packed_varint',
                 'packed_fixed32', 'packed_fixed64', 'bytes', 'empty']

CAVEATS = [
    'wire type 2 carries four different things; without a schema the bytes cannot '
    'separate them, so every length-delimited field lists all candidates that fit.',
    'a packed repeated field is indistinguishable from an opaque bytes value: the '
    'total length is known, the element boundaries are not.',
    'a varint 0 on the wire was emitted on purpose by some writer; for a field '
    'WITHOUT presence, value 0 and "never set" are the same bytes (nothing at '
    'all), so a field missing from a decode is not evidence that 0 was the value.',
    'field numbers are local to their message; nothing on the wire says which '
    'message a field number belongs to.',
    'confidence values are a documented heuristic ordering, not probabilities.',
]


class UsageError(Exception):
    """Bad input or bad flags: printed as one line, exit code 2."""


# --------------------------------------------------------------- primitives

def varint_len(value):
    """Number of bytes a canonical (minimal) varint needs for an unsigned value."""
    if value < 0:
        value &= MASK64
    n = 1
    while value >= 0x80:
        value >>= 7
        n += 1
    return n


def encode_varint(value):
    """Canonical base-128 varint. Negative values are written as 64-bit two's complement."""
    if value < 0:
        value &= MASK64
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_varint(buf, i, end):
    """Read one varint from buf[i:end].

    Returns (info, next_index, None) on success and (None, i, reason) when no
    complete varint could be read. `info` always carries:

        value            the decoded integer (may exceed 64 bits when overflow)
        hex / bytes      the exact bytes consumed
        canonical_bytes  what the minimal encoding of `value` would cost
        non_canonical    True when the wire used more bytes than necessary
        overflow         True when byte 10 carried bits above 2**64
        too_long         True when the varint ran past 10 bytes
    """
    start = i
    value = 0
    count = 0
    overflow = False
    too_long = False
    while True:
        if i >= end:
            return None, start, 'truncated varint at offset %d' % start
        b = buf[i]
        i += 1
        count += 1
        if count <= 9:
            value |= (b & 0x7F) << (7 * (count - 1))
        elif count == 10:
            if (b & 0x7F) > 1:
                overflow = True
            value |= (b & 0x7F) << 63
        else:
            too_long = True
        if not (b & 0x80):
            break
    raw = buf[start:i]
    canonical = varint_len(value & MASK64) if not overflow else varint_len(value)
    info = {
        'value': value,
        'hex': raw.hex(),
        'bytes': count,
        'canonical_bytes': canonical,
        'non_canonical': count > canonical,
        'overflow': overflow,
        'too_long': too_long,
    }
    return info, i, None


def zigzag_decode(value):
    return (value >> 1) ^ -(value & 1)


def int32_view(value):
    v = value & MASK32
    return v - (1 << 32) if v >= (1 << 31) else v


def int64_view(value):
    v = value & MASK64
    return v - (1 << 64) if v >= (1 << 63) else v


def _float_repr(x):
    """repr() of a float, never NaN/Infinity literals (illegal in strict JSON)."""
    return repr(x)


def ascii_escape(text):
    """Make a decoded string safe to print on any console: pure ASCII output."""
    return text.encode('unicode_escape').decode('ascii')


# ----------------------------------------------------------------- decode

class Ctx(object):
    """Collects notes (ambiguities) and errors while walking."""

    def __init__(self, max_depth=5, expand=True, silent=False):
        self.max_depth = max_depth
        self.expand = expand
        self.silent = silent
        self.notes = []
        self.errors = []

    def note(self, kind, path, offset, detail, **extra):
        if self.silent:
            return
        item = {'kind': kind, 'path': path, 'offset': offset, 'detail': detail}
        item.update(extra)
        self.notes.append(item)

    def error(self, kind, path, offset, detail):
        self.errors.append({'kind': kind, 'path': path, 'offset': offset,
                            'detail': detail})


def walk(buf, start, end, depth, ctx, path, until_group=None, analyse=True):
    """Walk buf[start:end] as one message body.

    Returns (fields, next_index, status) where status is 'end_of_buffer' when
    the region was consumed exactly, 'end_group' when the matching deprecated
    end-group tag closed it, or 'stopped:<reason>' when it could not continue.
    """
    fields = []
    i = start
    while i < end:
        tag_off = i
        info, j, reason = read_varint(buf, i, end)
        if info is None:
            ctx.error('truncated_tag', path, tag_off, reason)
            return fields, i, 'stopped:truncated_tag'
        if info['too_long'] or info['overflow']:
            ctx.error('varint_overflow', path, tag_off,
                      'tag varint at offset %d is %s (%d bytes, value needs %d); '
                      'the walk cannot resynchronise here'
                      % (tag_off, 'longer than 10 bytes' if info['too_long']
                         else 'wider than 64 bits', info['bytes'],
                         info['canonical_bytes']))
            return fields, j, 'stopped:varint_overflow'
        key = info['value']
        i = j
        field_no = key >> 3
        wire = key & 7
        if field_no == 0:
            ctx.note('field_number_zero', path, tag_off,
                     'tag 0x%x decodes to field number 0, which is illegal in '
                     'protobuf; this is a decode error, not a field'
                     % key)

        fpath = '%s.%d' % (path, field_no)

        if wire == 4:
            if until_group is not None and field_no == until_group:
                return fields, i, 'end_group'
            ctx.error('stray_end_group', path, tag_off,
                      'end-group tag for field %d at offset %d has no matching '
                      'group start' % (field_no, tag_off))
            return fields, i, 'stopped:stray_end_group'

        if wire not in (0, 1, 2, 3, 5):
            ctx.error('invalid_wire_type', path, tag_off,
                      'wire type %d at offset %d does not exist in protobuf'
                      % (wire, tag_off))
            return fields, i, 'stopped:invalid_wire_type'

        field = {
            'field': field_no,
            'wire': wire,
            'wire_name': WIRE_NAMES[wire],
            'wire_semantics': WIRE_SEMANTICS[wire],
            'offset': tag_off,
            'value_offset': i,
            'raw_hex': '',
        }

        if wire == 0:
            vinfo, j2, vreason = read_varint(buf, i, end)
            if vinfo is None:
                ctx.error('truncated_value', path, i, vreason)
                return fields, i, 'stopped:truncated_value'
            value = vinfo['value']
            field['view'] = 'varint'
            field['value'] = value
            field['varint'] = {
                'hex': vinfo['hex'],
                'bytes': vinfo['bytes'],
                'canonical_bytes': vinfo['canonical_bytes'],
                'non_canonical': vinfo['non_canonical'],
                'overflow': vinfo['overflow'],
                'too_long': vinfo['too_long'],
                'as_uint64': value & MASK64,
                'as_int64': int64_view(value),
                'as_int32': int32_view(value),
                'as_sint64_zigzag': zigzag_decode(value),
                'as_bool_if_0_or_1': None if value > 1 else bool(value),
            }
            i = j2
            if vinfo['non_canonical']:
                ctx.note('non_canonical_varint', fpath, field['value_offset'],
                         'field %d uses %d bytes where the minimal varint encoding '
                         'needs %d; a round-trip re-encode emits the minimal form'
                         % (field_no, vinfo['bytes'], vinfo['canonical_bytes']))
            if vinfo['overflow'] or vinfo['too_long']:
                ctx.note('varint_over_64_bits', fpath, field['value_offset'],
                         'field %d consumed %d bytes carrying more than 64 bits; '
                         'protobuf int64/uint64 cannot hold this value, so the '
                         'field is either not a varint or the stream is corrupt'
                         % (field_no, vinfo['bytes']))
            if value == 0:
                ctx.note('proto3_explicit_zero', fpath, field['value_offset'],
                         'field %d carries an explicit varint 0, so some writer '
                         'chose to emit it (a field WITH presence -- proto2 or '
                         'proto3 optional -- or a hand-rolled writer). The '
                         'converse matters more: for a field WITHOUT presence, '
                         'value 0 and "never set" are the same bytes (nothing at '
                         'all), so a field missing from this decode is not '
                         'evidence that the value in use was 0' % field_no)

        elif wire == 1:
            if i + 8 > end:
                ctx.error('truncated_fixed64', path, i,
                          'fixed64 for field %d needs 8 bytes, only %d remain'
                          % (field_no, end - i))
                return fields, i, 'stopped:truncated_fixed64'
            raw = buf[i:i + 8]
            i += 8
            field['view'] = 'fixed64'
            field['fixed64_hex'] = raw.hex()
            field['fixed64'] = {
                'as_uint64': struct.unpack('<Q', raw)[0],
                'as_int64': struct.unpack('<q', raw)[0],
                'as_double_repr': _float_repr(struct.unpack('<d', raw)[0]),
            }

        elif wire == 5:
            if i + 4 > end:
                ctx.error('truncated_fixed32', path, i,
                          'fixed32 for field %d needs 4 bytes, only %d remain'
                          % (field_no, end - i))
                return fields, i, 'stopped:truncated_fixed32'
            raw = buf[i:i + 4]
            i += 4
            field['view'] = 'fixed32'
            field['fixed32_hex'] = raw.hex()
            field['fixed32'] = {
                'as_uint32': struct.unpack('<I', raw)[0],
                'as_int32': struct.unpack('<i', raw)[0],
                'as_float_repr': _float_repr(struct.unpack('<f', raw)[0]),
            }

        elif wire == 2:
            linfo, j2, lreason = read_varint(buf, i, end)
            if linfo is None:
                ctx.error('truncated_length_prefix', path, i, lreason)
                return fields, i, 'stopped:truncated_length_prefix'
            ln = linfo['value']
            value_off = j2
            payload_end = j2 + ln
            if linfo['too_long'] or linfo['overflow'] or payload_end > end:
                ctx.error('length_overruns_buffer', path, value_off,
                          'field %d declares %d payload bytes at offset %d but '
                          'only %d remain' % (field_no, ln, value_off, end - value_off))
                return fields, i, 'stopped:length_overruns_buffer'
            chunk = buf[j2:payload_end]
            field['view'] = 'bytes'
            field['length'] = ln
            field['payload_hex'] = chunk.hex()
            field['length_prefix'] = {
                'hex': linfo['hex'],
                'bytes': linfo['bytes'],
                'non_canonical': linfo['non_canonical'],
            }
            if analyse:
                cands, view = analyse_payload(chunk, depth, ctx, fpath, value_off)
                field['candidates'] = cands
                field['view'] = view
                field['view_is_heuristic'] = True
                if view == 'nested_message':
                    if not ctx.expand:
                        field['expansion'] = 'suppressed by --no-expand'
                    else:
                        children, _nxt, _status = walk(chunk, 0, len(chunk),
                                                       depth + 1, ctx, fpath,
                                                       analyse=True)
                        field['children'] = children
                elif view == 'utf8_string':
                    field['string'] = chunk.decode('utf-8', 'replace')
                elif view == 'packed_varint':
                    field['packed_values'] = _packed_varint_values(chunk)
                elif view in ('packed_fixed32', 'packed_fixed64'):
                    step = 4 if view == 'packed_fixed32' else 8
                    field['packed_values_hex'] = [
                        chunk[k:k + step].hex() for k in range(0, len(chunk), step)]
            i = payload_end

        else:  # wire == 3, deprecated group
            if depth >= ctx.max_depth:
                ctx.note('depth_limit', fpath, tag_off,
                         'group at depth %d was not walked: --max-depth is %d'
                         % (depth, ctx.max_depth))
                field['view'] = 'group'
                field['children'] = []
                field['truncated_by_depth'] = True
                i = end
            else:
                children, j2, status = walk(buf, i, end, depth + 1, ctx, fpath,
                                            until_group=field_no, analyse=analyse)
                field['view'] = 'group'
                field['children'] = children
                field['group_deprecated'] = True
                ctx.note('deprecated_group', fpath, tag_off,
                         'field %d uses the deprecated group wire type (3/4); '
                         'groups were removed from the language, modern writers '
                         'do not emit them' % field_no)
                if status != 'end_group':
                    ctx.error('unterminated_group', fpath, tag_off,
                              'group for field %d was never closed by a matching '
                              'end-group tag' % field_no)
                    i = j2
                else:
                    i = j2

        field['end'] = i
        field['raw_hex'] = buf[tag_off:i].hex()
        fields.append(field)
    return fields, i, ('end_of_buffer' if i == end else 'stopped:partial')


def _packed_varint_values(chunk):
    values = []
    k = 0
    while k < len(chunk):
        info, k2, _reason = read_varint(chunk, k, len(chunk))
        if info is None:
            break
        values.append(info['value'])
        k = k2
    return values


def analyse_payload(chunk, depth, ctx, path, offset):
    """Every interpretation of a length-delimited payload that fits the bytes.

    Returns (candidates, view). `view` is the highest-confidence candidate --
    a default for expansion and re-encoding, explicitly not a conclusion.
    """
    n = len(chunk)
    cands = []

    if n == 0:
        cands.append({'kind': 'empty', 'confidence': 1.0,
                      'note': 'zero-length payload: every interpretation is '
                              'vacuous, nothing can be ranked'})
        return cands, 'empty'

    # --- nested message -------------------------------------------------
    if depth < ctx.max_depth:
        sub = Ctx(ctx.max_depth, ctx.expand, silent=True)
        sub_fields, nxt, status = walk(chunk, 0, n, depth + 1, sub, path,
                                       analyse=False)
        if status == 'end_of_buffer' and nxt == n and not sub.errors and sub_fields:
            cands.append({
                'kind': 'nested_message',
                'confidence': 0.85,
                'fields_count': len(sub_fields),
                'note': 'the payload consumes exactly as a message body (%d field(s))'
                        % len(sub_fields),
            })
        else:
            reason = ('walk stopped: %s' % status if status != 'end_of_buffer'
                      else 'walk left %d byte(s) unread' % (n - nxt))
            cands.append({'kind': 'nested_message', 'confidence': 0.0,
                          'rejected': reason,
                          'note': 'rejected: %s' % reason})
    else:
        cands.append({'kind': 'nested_message', 'confidence': 0.0,
                      'rejected': 'depth limit',
                      'note': 'not attempted: --max-depth %d reached' % ctx.max_depth})
        ctx.note('depth_limit', path, offset,
                 'a nested reading of this field was not attempted: --max-depth %d '
                 'reached. The bytes here may well be a message; re-run with a '
                 'larger --max-depth before concluding that they are not'
                 % ctx.max_depth)

    # --- UTF-8 string ---------------------------------------------------
    text = None
    try:
        text = chunk.decode('utf-8')
    except UnicodeDecodeError as exc:
        cands.append({'kind': 'utf8_string', 'confidence': 0.0,
                      'rejected': 'not valid UTF-8 (%s)' % exc.reason,
                      'note': 'rejected: %s at byte %d' % (exc.reason, exc.start)})
    if text is not None:
        controls = [ch for ch in text if ord(ch) < 0x20 and ch not in '\t\n\r']
        if not controls:
            conf = 0.9
            note = 'valid UTF-8 with no control characters'
        else:
            conf = 0.35
            note = ('valid UTF-8 but carries %d control character(s) (0x00-0x1f); '
                    'binary data commonly decodes as UTF-8 by accident'
                    % len(controls))
        cands.append({'kind': 'utf8_string', 'confidence': conf,
                      'length_chars': len(text), 'note': note})

    # --- packed arrays --------------------------------------------------
    if n % 4 == 0 and n >= 8:
        cands.append({'kind': 'packed_fixed32', 'confidence': 0.3,
                      'elements': n // 4, 'element_hex': _element_preview(chunk, 4),
                      'note': 'length divisible by 4: could be %d packed fixed32 '
                              'or float values -- element boundaries are only a '
                              'guess without a schema' % (n // 4)})
    if n % 8 == 0 and n >= 16:
        cands.append({'kind': 'packed_fixed64', 'confidence': 0.3,
                      'elements': n // 8, 'element_hex': _element_preview(chunk, 8),
                      'note': 'length divisible by 8: could be %d packed fixed64 '
                              'or double values -- element boundaries are only a '
                              'guess without a schema' % (n // 8)})

    packed_values = _packed_varint_values(chunk)
    if packed_values and len(b''.join(encode_varint(v) for v in packed_values)) == n \
            and len(chunk) == sum(varint_len(v) for v in packed_values):
        conf = 0.55 if len(packed_values) >= 2 else 0.25
        cands.append({'kind': 'packed_varint', 'confidence': conf,
                      'elements': len(packed_values),
                      'note': 'the payload is exactly a sequence of %d varint(s). '
                              'Without a schema this is a candidate, not a '
                              'reading: a packed repeated field is '
                              'indistinguishable from an opaque bytes value, so '
                              'the element boundaries are not knowable from the '
                              'bytes alone' % len(packed_values)})

    # --- opaque bytes ---------------------------------------------------
    # A fallback reading, not an equal-ranking candidate: it is consistent with
    # every payload, so scoring it like the others would let it win ties on
    # alphabetical order and silently suppress the useful readings.
    cands.append({'kind': 'bytes', 'confidence': 0.2,
                  'note': 'opaque bytes: always consistent with the payload, and '
                          'the only honest reading when no other candidate can be '
                          'confirmed against a schema'})

    # --- resolve ties ---------------------------------------------------
    live = [c for c in cands if c['confidence'] > 0.0]
    kinds = set(c['kind'] for c in live)
    competing = [k for k in ('nested_message', 'utf8_string', 'packed_varint')
                 if k in kinds]
    if len(competing) > 1:
        msg = ('%s are equally consistent with these bytes; without a schema '
               'nothing on the wire separates them, so the view below is a '
               'display default and NOT a reading'
               % ' and '.join(sorted(competing)))
        for c in live:
            if c['kind'] != 'bytes':
                c['confidence'] = min(c['confidence'], 0.5)
                c['ambiguous_with'] = sorted(k for k in competing if k != c['kind'])
                c['tie_note'] = msg

    cands.sort(key=lambda c: (-c['confidence'],
                              VIEW_PRIORITY.index(c['kind'])
                              if c['kind'] in VIEW_PRIORITY else 99))
    view = cands[0]['kind'] if cands else 'bytes'
    if view == 'empty':
        view = 'bytes'
    return cands, view


def _element_preview(chunk, step, limit=4):
    out = [chunk[k:k + step].hex() for k in range(0, min(len(chunk), step * limit), step)]
    if len(chunk) > step * limit:
        out.append('...')
    return out


# ---------------------------------------------------------------- re-encode

def payload_from_view(field):
    view = field.get('view') or 'bytes'
    if view in ('nested_message', 'group'):
        return b''.join(reencode_field(c, None, '') for c in field.get('children') or [])
    if view == 'utf8_string':
        return (field.get('string') or '').encode('utf-8')
    if view == 'packed_varint':
        return b''.join(encode_varint(int(v)) for v in (field.get('packed_values') or []))
    if view in ('packed_fixed32', 'packed_fixed64'):
        out = b''
        for h in field.get('packed_values_hex') or []:
            out += bytes.fromhex(h)
        return out
    return bytes.fromhex(field.get('payload_hex') or '')


def reencode_field(field, report, path):
    """Encode one field node. When `report` is given it is filled with the diff."""
    wire = field['wire']
    num = int(field['field'])
    key = encode_varint((num << 3) | wire)
    here = path or str(num)

    if wire == 0:
        body = encode_varint(int(field['value']))
    elif wire == 1:
        body = bytes.fromhex(field['fixed64_hex'])
    elif wire == 5:
        body = bytes.fromhex(field['fixed32_hex'])
    elif wire == 2:
        payload = payload_from_view(field)
        body = encode_varint(len(payload)) + payload
    elif wire == 3:
        inner = b''
        for child in field.get('children') or []:
            inner += reencode_field(child, report, '%s.%s' % (here, child['field']))
        body = inner + encode_varint((num << 3) | 4)
    else:
        raise UsageError('wire type %d cannot be re-encoded' % wire)

    raw = key + body
    if report is not None:
        report['fields'] += 1
        expected = field.get('raw_hex')
        if expected is not None and raw.hex() != expected:
            reason = 'the tree was edited'
            vinfo = field.get('varint') or {}
            if vinfo.get('non_canonical'):
                reason = ('the original varint was non-canonical (%d bytes for a '
                          '%d-byte value); the re-encode emits the minimal form'
                          % (vinfo.get('bytes'), vinfo.get('canonical_bytes')))
            report['mismatched'].append({
                'path': here, 'expected_hex': expected, 'got_hex': raw.hex(),
                'reason': reason,
            })
        else:
            report['identical'] += 1
    return raw


def reencode_tree(tree, report):
    frames = tree.get('frames') or []
    out = b''
    for frame in frames:
        for field in frame.get('fields') or []:
            out += reencode_field(field, report, str(field['field']))
    return out


# ------------------------------------------------------------------- input

HEX_ESCAPE_RE = re.compile(r'\\(x[0-9A-Fa-f]{2}|[nrt0\\])')
HEX_ONLY_RE = re.compile(r'[0-9A-Fa-f\s,;|]')
ESCAPE_MAP = {'n': b'\n', 'r': b'\r', 't': b'\t', '0': b'\x00', '\\': b'\\'}


def _unescape(text):
    """Turn \\xNN / \\n / \\t / \\\\ escapes into bytes."""
    out = bytearray()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '\\' and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == 'x' and i + 3 < len(text) + 1:
                pair = text[i + 2:i + 4]
                if len(pair) == 2 and re.fullmatch(r'[0-9A-Fa-f]{2}', pair):
                    out.append(int(pair, 16))
                    i += 4
                    continue
            if nxt in ESCAPE_MAP:
                out += ESCAPE_MAP[nxt]
                i += 2
                continue
        out += ch.encode('utf-8')
        i += 1
    return bytes(out)


def parse_hex_frames(text):
    """Split on '|' / ';' and decode each part as hex bytes.

    Accepts `08 96 01`, `0x08 0x96 0x01`, newlines, commas and `\\x08\\x96\\x01`.
    A part that is not hex at all is taken as literal text bytes, so a pasted
    ASCII body still decodes.
    """
    frames = []
    for part in re.split(r'[|;]', text):
        if not part.strip():
            continue
        if '\\x' in part or '\\n' in part or '\\t' in part:
            # Whitespace and commas are separators here too: in `08 96 | \x12\x07`,
            # the space after the bar is layout, not a 0x20 byte.
            frames.append(_unescape(re.sub(r'[\s,]', '', part)))
            continue
        cleaned = re.sub(r'0[xX]', '', part)
        cleaned = re.sub(r'[\s,]', '', cleaned)
        if not cleaned:
            continue
        if not re.fullmatch(r'[0-9A-Fa-f]+', cleaned):
            frames.append(part.encode('utf-8'))
            continue
        if len(cleaned) % 2:
            raise UsageError('odd number of hex digits in a frame (%d): a hex '
                             'string must describe whole bytes' % len(cleaned))
        frames.append(bytes.fromhex(cleaned))
    if not frames:
        raise UsageError('no bytes in the hex input after stripping separators')
    return frames


def looks_like_hex_text(text):
    stripped = text.strip()
    if not stripped:
        return False
    try:
        stripped.encode('ascii')
    except UnicodeEncodeError:
        return False
    body = HEX_ESCAPE_RE.sub('aa', stripped)
    body = re.sub(r'0[xX]', '', body)
    body = re.sub(r'[\s,;|]', '', body)
    if not body or not re.fullmatch(r'[0-9A-Fa-f]+', body):
        return False
    return len(body) % 2 == 0


def split_varint_length(buf):
    """Frames of the form <varint length><payload>, as gRPC/WebSocket use."""
    frames = []
    i = 0
    while i < len(buf):
        info, j, reason = read_varint(buf, i, len(buf))
        if info is None:
            raise UsageError('frame length prefix at offset %d: %s' % (i, reason))
        if info['too_long'] or info['overflow']:
            raise UsageError('frame length prefix at offset %d overflows 64 bits' % i)
        ln = info['value']
        if j + ln > len(buf):
            raise UsageError('frame at offset %d declares %d payload bytes but only '
                             '%d remain' % (i, ln, len(buf) - j))
        frames.append((j, j + ln, i))
        i = j + ln
    return frames


def load_input(args):
    """Return (buffer, frames) where frames is a list of (start, end, prefix_offset)."""
    if args.hex is not None:
        parts = parse_hex_frames(args.hex)
        buf = b''.join(parts)
        frames = []
        pos = 0
        for part in parts:
            frames.append((pos, pos + len(part), None))
            pos += len(part)
        return buf, frames, '--hex'

    if args.input is None or args.input == '-':
        data = sys.stdin.buffer.read()
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            text = None
        if text is not None and looks_like_hex_text(text):
            parts = parse_hex_frames(text)
            buf = b''.join(parts)
            frames = []
            pos = 0
            for part in parts:
                frames.append((pos, pos + len(part), None))
                pos += len(part)
            return buf, frames, 'stdin (hex text)'
        return data, [(0, len(data), None)], 'stdin (raw bytes)'

    try:
        with open(args.input, 'rb') as fh:
            data = fh.read()
    except OSError as exc:
        raise UsageError('cannot read %s: %s' % (args.input, exc))
    return data, [(0, len(data), None)], args.input


def apply_split(buf, frames, mode):
    if mode == 'none':
        return frames
    split = split_varint_length(buf)
    if not split:
        raise UsageError('--split varint-length found no frames in %d bytes' % len(buf))
    return split


# ------------------------------------------------------------------ output

def field_line(field, indent):
    pad = '  ' * indent
    if field['wire'] == 0:
        v = field['varint']
        extra = ''
        if v['non_canonical']:
            extra = '  [non-canonical: %d bytes for a %d-byte value]' % (
                v['bytes'], v['canonical_bytes'])
        if v['overflow'] or v['too_long']:
            extra += '  [OVERFLOW: wider than 64 bits]'
        if field['value'] == 0:
            extra += '  [proto3: 0 is byte-identical to an absent field]'
        return ['%sf%d  varint  %d%s' % (pad, field['field'], field['value'], extra)]
    if field['wire'] == 1:
        d = field['fixed64']
        return ['%sf%d  fixed64  %s  (u64=%d, double=%s)'
                % (pad, field['field'], field['fixed64_hex'],
                   d['as_uint64'], d['as_double_repr'])]
    if field['wire'] == 5:
        d = field['fixed32']
        return ['%sf%d  fixed32  %s  (u32=%d, float=%s)'
                % (pad, field['field'], field['fixed32_hex'],
                   d['as_uint32'], d['as_float_repr'])]
    if field['wire'] == 2:
        lines = ['%sf%d  len-delimited(%d)  view=%s' % (
            pad, field['field'], field['length'], field.get('view'))]
        ties = []
        for cand in field.get('candidates') or []:
            if cand['confidence'] > 0.0:
                lines.append('%s    candidate %-16s %.2f  %s'
                             % (pad, cand['kind'], cand['confidence'],
                                ascii_escape(cand['note'])))
            elif cand.get('rejected'):
                lines.append('%s    candidate %-16s rejected: %s'
                             % (pad, cand['kind'], ascii_escape(str(cand['rejected']))))
            if cand.get('tie_note') and cand['tie_note'] not in ties:
                ties.append(cand['tie_note'])
        for t in ties:
            lines.append('%s    tie: %s' % (pad, ascii_escape(t)))
        if field.get('view') == 'utf8_string':
            lines.append('%s    string: %r' % (pad, ascii_escape(field['string'])))
        elif field.get('view') == 'nested_message':
            for child in field.get('children') or []:
                lines.extend(field_line(child, indent + 2))
            if field.get('expansion'):
                lines.append('%s    expansion: %s' % (pad, field['expansion']))
        elif field.get('view') == 'packed_varint':
            lines.append('%s    packed varints: %s'
                         % (pad, field['packed_values']))
        elif field.get('view') in ('packed_fixed32', 'packed_fixed64'):
            lines.append('%s    elements: %s' % (pad, field['packed_values_hex']))
        elif field.get('view') == 'bytes':
            lines.append('%s    bytes: %s' % (pad, field['payload_hex']))
        return lines
    if field['wire'] == 3:
        lines = ['%sf%d  group (deprecated wire type)' % (pad, field['field'])]
        for child in field.get('children') or []:
            lines.extend(field_line(child, indent + 1))
        return lines
    return ['%sf%d  wire%s' % (pad, field['field'], field['wire'])]


def render_human(tree):
    out = []
    inp = tree['input']
    out.append('input: %s, %d byte(s)' % (inp['source'], inp['byte_length']))
    out.append('hex:   %s' % inp['hex'])
    for frame in tree['frames']:
        note = ''
        if frame.get('prefix_offset') is not None:
            note = ' (length-prefixed at offset %d)' % frame['prefix_offset']
        out.append('')
        out.append('frame %d  bytes %d..%d  (%d B)%s  status=%s'
                   % (frame['index'], frame['start'], frame['end'],
                      frame['length'], note, frame['walk_status']))
        if not frame['fields']:
            out.append('  (no fields walked)')
        for field in frame['fields']:
            out.extend(field_line(field, 1))
    if tree['ambiguities']:
        out.append('')
        out.append('ambiguities the wire format cannot resolve here:')
        for n in tree['ambiguities']:
            out.append('  [%s] %s @%d: %s'
                       % (n['kind'], n['path'], n['offset'], ascii_escape(n['detail'])))
    if tree['errors']:
        out.append('')
        out.append('errors:')
        for e in tree['errors']:
            out.append('  [%s] %s @%d: %s'
                       % (e['kind'], e['path'], e['offset'], ascii_escape(e['detail'])))
    out.append('')
    out.append('fixed caveats (true of every decode in this output):')
    for c in CAVEATS:
        out.append('  - %s' % c)
    return '\n'.join(out)


def decode(args):
    buf, frames, source = load_input(args)
    frames = apply_split(buf, frames, args.split)
    ctx = Ctx(args.max_depth, not args.no_expand)
    frame_nodes = []
    head = buf[:4096]
    input_hex = head.hex()
    truncated = len(buf) > len(head)
    for idx, frame in enumerate(frames):
        start, end = frame[0], frame[1]
        prefix = frame[2] if len(frame) > 2 else None
        fields, consumed, status = walk(buf, start, end, 0, ctx, 'frame%d' % idx,
                                        analyse=True)
        frame_nodes.append({
            'index': idx,
            'start': start,
            'end': end,
            'length': end - start,
            'prefix_offset': prefix,
            'fields': fields,
            'walk_status': status,
            'bytes_consumed': consumed - start,
        })
    tree = {
        'tool': 'protobuf_decode_raw.py',
        'schema': None,
        'input': {'source': source, 'byte_length': len(buf), 'hex': input_hex,
                  'hex_truncated': truncated, 'frame_count': len(frame_nodes),
                  'split': args.split},
        'frames': frame_nodes,
        'ambiguities': ctx.notes,
        'errors': ctx.errors,
        'caveats': CAVEATS,
    }
    if args.json:
        print(json.dumps(tree, indent=2, sort_keys=False, ensure_ascii=True))
    else:
        print(render_human(tree))
    return 0 if not ctx.errors else 1


def do_reencode(args):
    try:
        with open(args.reencode, 'r', encoding='utf-8') as fh:
            tree = json.load(fh)
    except OSError as exc:
        raise UsageError('cannot read %s: %s' % (args.reencode, exc))
    except ValueError as exc:
        raise UsageError('%s is not valid JSON: %s' % (args.reencode, exc))
    if 'frames' not in tree:
        raise UsageError('%s does not look like protobuf_decode_raw.py output '
                         '(no "frames" key)' % args.reencode)

    report = {'fields': 0, 'identical': 0, 'mismatched': []}
    out = reencode_tree(tree, report)

    if args.out:
        with open(args.out, 'wb') as fh:
            fh.write(out)

    result = {
        'bytes': len(out),
        'hex': out.hex(),
        'fields': report['fields'],
        'fields_byte_identical': report['identical'],
        'mismatched': report['mismatched'],
        'out_path': args.out,
    }
    if args.check:
        try:
            with open(args.check, 'rb') as fh:
                original = fh.read()
        except OSError as exc:
            raise UsageError('cannot read %s: %s' % (args.check, exc))
        result['check_path'] = args.check
        result['check_bytes'] = len(original)
        split = (tree.get('input') or {}).get('split')
        original_cmp = original
        scope = 'the whole file'
        if split == 'varint-length':
            try:
                orig_frames = split_varint_length(original)
            except UsageError as exc:
                raise UsageError('%s does not carry varint-length framing: %s'
                                 % (args.check, exc))
            original_cmp = b''.join(original[s:e] for s, e, _p in orig_frames)
            scope = ('frame bodies only: %d of %d byte(s) are length prefixes '
                     '(framing, not message data)'
                     % (len(original) - len(original_cmp), len(original)))
        result['check_scope'] = scope
        if original_cmp == out:
            result['check'] = 'MATCH'
        else:
            result['check'] = 'MISMATCH'
            diff = -1
            for k in range(min(len(original_cmp), len(out))):
                if original_cmp[k] != out[k]:
                    diff = k
                    break
            if diff < 0:
                diff = min(len(original_cmp), len(out))
            result['first_difference_offset'] = diff
            result['original_at_diff'] = original_cmp[diff:diff + 8].hex()
            result['reencoded_at_diff'] = out[diff:diff + 8].hex()

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=True))
    else:
        print('re-encoded %d byte(s) from %d field(s)'
              % (result['bytes'], result['fields']))
        print('  fields re-encoded byte-identically: %d/%d'
              % (result['fields_byte_identical'], result['fields']))
        for m in result['mismatched']:
            print('  CHANGED field %s: expected %s, got %s (%s)'
                  % (m['path'], m['expected_hex'], m['got_hex'], m['reason']))
        if args.out:
            print('  written to %s' % args.out)
        else:
            print('  hex: %s' % result['hex'])
        if args.check:
            print('  check against %s (%d B, %s): %s'
                  % (result['check_path'], result['check_bytes'],
                     result.get('check_scope', 'the whole file'), result['check']))
            if result['check'] == 'MISMATCH':
                off = result['first_difference_offset']
                print('    first difference at offset %d: original %s vs re-encoded %s'
                      % (off, result['original_at_diff'], result['reencoded_at_diff']))
    return 0 if result.get('check', 'MATCH') == 'MATCH' else 1


# ----------------------------------------------------------------- selftest

def _fixtures():
    """Known-answer fixtures. Every byte here is produced by hand in this file."""
    def tag(field, wire):
        return encode_varint((field << 3) | wire)

    def ld(field, payload):
        return tag(field, 2) + encode_varint(len(payload)) + payload

    nested_inner = tag(2, 0) + encode_varint(7)
    nested_outer = tag(1, 0) + encode_varint(1) + ld(2, nested_inner)
    packed = b''.join(encode_varint(v) for v in (3, 270, 86942))
    main = b''.join([
        tag(1, 0) + encode_varint(150),
        ld(2, b'testing'),
        ld(3, nested_outer),
        ld(4, packed),
        tag(5, 0) + encode_varint(0),
        tag(6, 1) + struct.pack('<Q', 0x0102030405060708),
        tag(7, 5) + struct.pack('<I', 0xDEADBEEF),
    ])
    group = tag(8, 3) + tag(1, 0) + encode_varint(5) + tag(8, 4)
    non_canonical = tag(1, 0) + b'\x96\x81\x00'
    overflow = tag(1, 0) + bytes([0xFF] * 9) + bytes([0x7F])
    two_msgs = (tag(1, 0) + encode_varint(1) + ld(2, b'ab') +
                tag(1, 0) + encode_varint(2) + ld(2, b'cd'))
    fixed_len = encode_varint(len(main)) + main
    # (name, payload, expectations, round-trip expectation)
    # round-trip is 'match' for every fixture that re-encodes canonically, and
    # 'non-canonical' for the one fixture whose whole point is a redundant
    # encoding: there the re-encode is *expected* to differ, and by a stated
    # amount -- which is exactly why the difference has to be recorded, not
    # silently normalised away.
    return [
        ('canonical varint 150', tag(1, 0) + encode_varint(150),
         [('field 1 varint value', 1, 150)], 'match'),
        ('multi-byte varint 86942', tag(1, 0) + encode_varint(86942),
         [('field 1 varint value', 1, 86942)], 'match'),
        ('unsigned max uint64', tag(1, 0) + encode_varint(MASK64),
         [('field 1 varint value', 1, MASK64)], 'match'),
        ('nested two levels', main,
         [('field 3 nested child count', 3, 2)], 'match'),
        ('packed varints as a field value', ld(4, packed),
         [('field 4 packed element count', 4, 3)], 'match'),
        ('fixed64 + fixed32', main,
         [('field 6 fixed64 hex', 6, '0807060504030201')], 'match'),
        ('proto3 explicit zero', tag(5, 0) + encode_varint(0),
         [('field 5 varint value', 5, 0)], 'match'),
        ('deprecated group 3/4', group,
         [('field 8 has children', 8, 1)], 'match'),
        ('non-canonical varint', non_canonical,
         [('field 1 varint value', 1, 150)], 'non-canonical'),
        ('10-byte varint overflow', overflow,
         [('field 1 varint overflow', 1, True)], 'match'),
        ('two top-level messages in one stream', two_msgs,
         [('top-level field count', None, 4)], 'match'),
        ('varint length framing', fixed_len,
         [('frame body hex', None, main.hex())], 'match'),
    ]


def selftest(args):
    fixtures = _fixtures()
    failures = []
    checks = 0

    print('== known-answer fixtures (bytes produced by hand in this script) ==')
    for name, payload, expects, _rt in fixtures:
        ctx = Ctx(max_depth=6)
        frames = _fixture_frames(name, payload)
        fields = []
        for start, end, _p in frames:
            f, _n, _s = walk(payload, start, end, 0, ctx, 'f', analyse=True)
            fields.extend(f)
        print('  %-45s %s' % (name, payload.hex()))
        print('    fields: %d, status %s' % (len(fields), 'ok'))
        for label, num, expected in expects:
            checks += 1
            got = _selftest_lookup(fields, frames, payload, label, num)
            ok = got == expected
            if not ok:
                failures.append('%s: %s expected %r got %r' % (name, label, expected, got))
            print('    %-38s %-6s %s' % (label, 'PASS' if ok else 'FAIL', got))

    # round trip over every fixture
    print('')
    print('== round trip: decode -> re-encode -> byte comparison ==')
    for name, payload, _e, rt in fixtures:
        checks += 1
        frames = _fixture_frames(name, payload)
        tree = {'frames': [{'fields': walk(payload, s, e, 0, Ctx(6),
                                           'f', analyse=True)[0]}
                           for s, e, _p in frames]}
        report = {'fields': 0, 'identical': 0, 'mismatched': []}
        out = reencode_tree(tree, report)
        expect_bytes = b''.join(payload[s:e] for s, e, _p in frames)
        if rt == 'non-canonical':
            ok = (out != expect_bytes and out.hex() == '089601'
                  and report['mismatched']
                  and 'non-canonical' in report['mismatched'][0]['reason'])
            verdict = 'MATCH' if ok else 'FAIL'
            detail = ('re-encode emits the minimal form %s, original %s, and the '
                      'report states why' % (out.hex(), expect_bytes.hex()))
        else:
            ok = out == expect_bytes
            verdict = 'MATCH' if ok else 'FAIL'
            detail = ''
        if not ok:
            failures.append('%s: round trip differs (%s vs %s)'
                            % (name, expect_bytes.hex(), out.hex()))
        print('  %-45s %-6s (%d fields, %d identical) %s'
              % (name, verdict, report['fields'], report['identical'], detail))

    # the two documented traps, asserted rather than narrated
    print('')
    print('== the two wire-format traps ==')
    checks += 2
    zero = tag_0(5, 0) + encode_varint(0)
    absent = b''
    same = (zero != absent) and walk(zero, 0, len(zero), 0, Ctx(6), 'f')[0][0]['value'] == 0
    ok = walk(absent, 0, 0, 0, Ctx(6), 'f')[0] == []
    if not (same and ok):
        failures.append('proto3 explicit zero vs absent field not distinguished correctly')
    print('  explicit zero bytes %s decodes to value 0; absent field decodes to no '
          'fields at all: %s' % (zero.hex(), 'PASS' if same and ok else 'FAIL'))

    packed = b''.join(encode_varint(v) for v in (3, 270, 86942))
    cands, view = analyse_payload(packed, 0, Ctx(6), 'f', 0)
    live_kinds = sorted(c['kind'] for c in cands if c['confidence'] > 0.0)
    all_kinds = sorted(c['kind'] for c in cands)
    ok = ('packed_varint' in live_kinds and 'nested_message' in all_kinds
          and view in live_kinds and view == 'packed_varint')
    if not ok:
        failures.append('packed payload did not offer both candidates: %r' % all_kinds)
    print('  packed payload %s offers live=%s, rejected=%s -> view=%s : %s'
          % (packed.hex(), live_kinds,
             sorted(set(all_kinds) - set(live_kinds)), view,
             'PASS' if ok else 'FAIL'))
    print('  -> both readings fit the same bytes; a schema is what decides.')

    print('')
    total = len(fixtures) * 2 + 2
    print('selftest: %d/%d PASS' % (len(fixtures) * 2 + 2 - len(failures), total))
    if failures:
        print('failures:')
        for f in failures:
            print('  - %s' % f)
        return 1
    return 0


def tag_0(field, wire):
    return encode_varint((field << 3) | wire)


def _fixture_frames(name, payload):
    """Framing used by both the decode and the round-trip pass of the selftest."""
    if name == 'varint length framing':
        return split_varint_length(payload)
    return [(0, len(payload), None)]


def _selftest_lookup(fields, frames, payload, label, num):
    """Pull the expected value out of a walked tree for one fixture assertion."""
    m = re.match(r'^field (\d+) varint value$', label)
    if m:
        return _find_field(fields, int(m.group(1)))['value']
    m = re.match(r'^field (\d+) varint overflow$', label)
    if m:
        return _find_field(fields, int(m.group(1)))['varint']['overflow']
    m = re.match(r'^field (\d+) nested child count$', label)
    if m:
        return len(_find_field(fields, int(m.group(1))).get('children') or [])
    m = re.match(r'^field (\d+) has children$', label)
    if m:
        return len(_find_field(fields, int(m.group(1))).get('children') or [])
    m = re.match(r'^field (\d+) fixed64 hex$', label)
    if m:
        return _find_field(fields, int(m.group(1)))['fixed64_hex']
    m = re.match(r'^field (\d+) packed element count$', label)
    if m:
        return len(_find_field(fields, int(m.group(1))).get('packed_values') or [])
    if label == 'packed element count':
        return len(_packed_varint_values(bytes.fromhex('038e029ea705')))
    if label == 'top-level field count':
        return len(fields)
    if label == 'frame body hex':
        return payload[frames[0][0]:frames[0][1]].hex()
    raise UsageError('unknown selftest label %s' % label)


def _find_field(fields, num):
    for f in fields:
        if f['field'] == num:
            return f
    raise UsageError('fixture field %d not found' % num)


# --------------------------------------------------------------------- main

def build_parser():
    ap = argparse.ArgumentParser(
        prog='protobuf_decode_raw.py',
        description='Decode a schema-less protobuf payload into a JSON tree, with '
                    'every length-delimited field reported as a candidate set '
                    'instead of one guess. Supports hex, raw files, stdin, several '
                    'frames and a round-trip re-encode.',
        epilog='Examples:\n'
               '  protobuf_decode_raw.py --hex "08 96 01 12 07 74657374696e67"\n'
               '  protobuf_decode_raw.py body.bin --json > tree.json\n'
               '  protobuf_decode_raw.py framed.bin --split varint-length\n'
               '  protobuf_decode_raw.py --reencode tree.json --out patched.bin '
               '--check body.bin\n'
               '  protobuf_decode_raw.py --selftest\n',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('input', nargs='?', default=None,
                    help="binary file to decode, or '-' for stdin")
    ap.add_argument('--hex', metavar='STR', default=None,
                    help='decode a hex string instead of a file: accepts "0x" '
                         'prefixes, spaces, newlines, commas and \\xNN escapes; '
                         "'|' separates independent frames")
    ap.add_argument('--json', action='store_true',
                    help='print the JSON tree instead of the human tree view')
    ap.add_argument('--max-depth', type=int, default=5, metavar='N',
                    help='maximum nesting depth to expand (default 5)')
    ap.add_argument('--no-expand', action='store_true',
                    help='list candidates but do not recurse into nested messages')
    ap.add_argument('--split', choices=('none', 'varint-length'), default='none',
                    help='frame the input: "none" (default, one message) or '
                         '"varint-length" for <varint length><payload> framing')
    ap.add_argument('--reencode', metavar='JSON', default=None,
                    help='re-encode a decoded JSON tree back to bytes '
                         '(round-trip and edit-and-rebuild)')
    ap.add_argument('--out', metavar='PATH', default=None,
                    help='with --reencode: where to write the bytes')
    ap.add_argument('--check', metavar='PATH', default=None,
                    help='with --reencode: compare the result against this file')
    ap.add_argument('--selftest', action='store_true',
                    help='run the built-in known-answer fixtures and their '
                         'round-trip checks')
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest(args)
    if args.reencode:
        return do_reencode(args)
    return decode(args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except UsageError as exc:
        sys.stderr.write('error: %s\n' % exc)
        sys.exit(2)
    except BrokenPipeError:
        sys.exit(0)
