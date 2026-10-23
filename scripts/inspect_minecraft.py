import argparse
import hashlib
import json
from pathlib import Path
from signature_tools import Elf, branch_target, find_matches, parse_pattern


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description='Inspect IDA byte signatures, unwind entries, call relationships and RTTI. No automatic retargeting.')
    parser.add_argument('library', type=Path)
    parser.add_argument('--signatures', type=Path, default=root / 'lightdocs/reference/signatures.json')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--vtable')
    parser.add_argument('--slots', type=int, default=32)
    parser.add_argument('--dump-rva', type=lambda value: int(value, 0))
    parser.add_argument('--size', type=lambda value: int(value, 0), default=256)
    args = parser.parse_args()
    image = Elf(args.library)
    profile = json.loads(args.signatures.read_text())
    report = {'file': str(args.library.resolve()), 'file_bytes': len(image.data), 'sha256': hashlib.sha256(image.data).hexdigest(), 'build_id': image.build_id(), 'baseline_build_id': profile['build_id'], 'baseline_identity_matches': image.build_id() == profile['build_id'], 'targets': [], 'references': [], 'device_tested': False}
    segments = list(image.executable())
    anchors, addresses = {}, {}
    complete = True
    for source in profile['functions']:
        pattern = parse_pattern(source['pattern'])
        hits = find_matches(segments, pattern)
        file_hits = find_matches([(0, image.data)], pattern)
        owner = image.function_entry(hits[0], len(pattern)) if len(hits) == 1 else None
        entry = owner
        item = {'id': source['id'], 'baseline_rva': source['rva'], 'resolve': source['resolve'], 'byte_signature': source['pattern'], 'length': len(pattern), 'signature_matches': [hex(value) for value in hits], 'mapped_match_count': len(hits), 'whole_file_matches': [hex(value) for value in file_hits], 'whole_file_match_count': len(file_hits), 'at_least_two_matches': len(hits) > 1 or len(file_hits) > 1, 'anchor_function': hex(owner) if owner is not None else None}
        if entry is not None and source['resolve'] == 'call':
            try:
                offset = source['anchor_call_offset']
                if offset < 0 or offset + 4 > len(pattern):
                    raise ValueError('BL lies outside matched byte signature')
                call = hits[0] + offset
                entry = branch_target(image.words(call, 4)[0], call)
                if image.function_entry(entry, 4) != entry:
                    raise ValueError('BL target is not a function entry')
            except ValueError as error:
                item['error'] = str(error)
                entry = None
        item['resolved_entry'] = hex(entry) if entry is not None else None
        report['targets'].append(item)
        if entry is None or len(file_hits) != 1:
            complete = False
        else:
            anchors[source['id']] = hits[0]
            addresses[source['id']] = entry
    for reference in profile['references']:
        item = {'id': reference['id'], 'source': reference['source'], 'resolved_target': None, 'consistent': False}
        try:
            call = anchors[reference['source']] + reference['anchor_call_offset']
            target = branch_target(image.words(call, 4)[0], call)
            consistent = addresses.get(reference['id']) == target
            item.update(resolved_target=hex(target), consistent=consistent)
            if not consistent:
                complete = False
        except (KeyError, ValueError) as error:
            item['error'] = str(error)
            complete = False
        report['references'].append(item)
    tables = image.vtables('24MinecraftUIRenderContext')
    report['ui_vtable'] = [hex(value) for value in tables]
    report['resolution_complete'] = complete and len(addresses) == 18 and len(tables) == 1
    report['layout_compatibility'] = 'Object offsets and native ABI still require review for a new build.'
    if args.vtable:
        report['vtables'] = [{'name': args.vtable, 'address_point': hex(table), 'entries': [{'slot': slot, 'rva': hex(image.u64(table + slot * 8))} for slot in range(max(0, min(args.slots, 1024)))]} for table in image.vtables(args.vtable)]
    if args.dump_rva is not None:
        try:
            from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        except ImportError as error:
            raise SystemExit('Install capstone to use --dump-rva') from error
        engine = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        report['disassembly'] = [{'rva': hex(item.address), 'bytes': item.bytes.hex(' '), 'instruction': item.mnemonic + ' ' + item.op_str} for item in engine.disasm(image.read(args.dump_rva, args.size), args.dump_rva)]
    content = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.write_text(content)
    else:
        print(content, end='')


if __name__ == '__main__':
    main()
