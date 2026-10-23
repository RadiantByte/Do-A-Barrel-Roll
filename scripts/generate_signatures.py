import argparse
import csv
import json
from pathlib import Path
from signature_tools import Elf, branch_target, find_matches, format_pattern, sigmaker_pattern


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument('library', type=Path)
    parser.add_argument('--sources', type=Path, default=root / 'lightdocs/reference/signature-sources.json')
    include = root / 'include'
    if (include / 'android').is_dir():
        include = include / 'android'
    parser.add_argument('--output', type=Path, default=include / 'dabr/Signatures.hpp')
    parser.add_argument('--reference', type=Path, default=root / 'lightdocs/reference')
    args = parser.parse_args()
    image = Elf(args.library)
    sources = json.loads(args.sources.read_text())
    if image.build_id() != sources['build_id']:
        raise ValueError('Source addresses belong to another build; recover and review the new addresses first')
    segments = list(image.executable())
    generated = []
    for source in sources['functions'] + sources['helpers']:
        helper = 'source_rva' in source
        owner = int(source['source_rva'] if helper else source['rva'], 16)
        address = owner + source['anchor_offset']
        full = sigmaker_pattern(image.read(address, source['maximum_size']), address)
        matches, file_matches, pattern = [], [], []
        for size in range(source['minimum_size'], source['maximum_size'] + 1, 4):
            pattern = full[:size]
            if len(pattern) != size or image.function_entry(address, size) != owner:
                break
            matches = find_matches(segments, pattern)
            file_matches = find_matches([(0, image.data)], pattern)
            if matches == [address] and file_matches == [image.offset(address)]:
                break
        else:
            raise ValueError(f"No unique byte signature inside {source['id']}")
        if matches != [address] or file_matches != [image.offset(address)]:
            raise ValueError(f"No unique in-function byte signature for {source['id']}")
        call_offset = source['call_offset'] - source['anchor_offset'] if helper else 0
        if helper:
            if call_offset < 0 or call_offset + 4 > len(pattern):
                raise ValueError(f"Call falls outside {source['id']} byte signature")
            target = branch_target(image.words(address + call_offset, 4)[0], address + call_offset)
            if target != int(source['rva'], 16) or image.function_entry(target, 4) != target:
                raise ValueError(f"Incorrect call target for {source['id']}")
        generated.append(dict(source, resolve='call' if helper else 'function', pattern=format_pattern(pattern), byte_count=len(pattern), anchor_rva=hex(address), match_count=len(matches), matches=[hex(value) for value in matches], file_match_count=len(file_matches), file_matches=[hex(value) for value in file_matches], anchor_call_offset=call_offset))
    references = []
    for source in sources['references']:
        caller = next(item for item in generated if item['id'] == source['source'])
        call = int(caller['rva'], 16) + source['call_offset']
        target = branch_target(image.words(call, 4)[0], call)
        if target != int(source['rva'], 16):
            raise ValueError(f"Reference mismatch for {source['id']}")
        anchor_call_offset = source['call_offset'] - caller['anchor_offset']
        if anchor_call_offset < 0 or anchor_call_offset + 4 > caller['byte_count']:
            raise ValueError(f"Reference falls outside {source['source']} signature")
        references.append(dict(source, anchor_call_offset=anchor_call_offset))
    ids = [source['id'] for source in generated]
    header = '''#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace dabr::build {
enum class Symbol { ''' + ', '.join(ids) + ''', Count };
enum class ResolveKind { Function, Call };
struct CodeSpec { Symbol id; std::string_view pattern; ResolveKind resolve; std::size_t callOffset; };
struct ReferenceSpec { Symbol id, source; std::size_t callOffset; };
inline constexpr std::array<CodeSpec, ''' + str(len(generated)) + '> Code{{\n'
    for item in generated:
        kind = 'Call' if item['resolve'] == 'call' else 'Function'
        header += f'    {{Symbol::{item["id"]},\n        "{item["pattern"]}", ResolveKind::{kind}, {item["anchor_call_offset"]}}},\n'
    header += '}};\ninline constexpr std::array<ReferenceSpec, ' + str(len(references)) + '> References{{\n'
    header += ''.join(f'    {{Symbol::{item["id"]}, Symbol::{item["source"]}, {item["anchor_call_offset"]}}},\n' for item in references)
    header += '}};\n}\n'
    args.output.write_text(header)
    args.reference.mkdir(parents=True, exist_ok=True)
    profile = {'build_id': image.build_id(), 'format': 'IDA byte signatures', 'pattern_policy': sources['pattern_policy'], 'functions': generated, 'references': references}
    (args.reference / 'signatures.json').write_text(json.dumps(profile, indent=2) + '\n')
    with (args.reference / 'signatures.csv').open('w', newline='') as output:
        writer = csv.writer(output)
        writer.writerow(['id', 'baseline_rva', 'resolve', 'anchor_rva', 'call_offset_from_match', 'length', 'mapped_matches', 'whole_file_matches', 'byte_signature'])
        for item in generated:
            writer.writerow([item['id'], item['rva'], item['resolve'], item['anchor_rva'], hex(item['anchor_call_offset']), item['byte_count'], item['match_count'], item['file_match_count'], item['pattern']])
    for item in generated:
        print(f"{item['id']}: {item['byte_count']} bytes; mapped hits {item['match_count']}; whole-file hits {item['file_match_count']}; target {item['rva']}", flush=True)


if __name__ == '__main__':
    main()
