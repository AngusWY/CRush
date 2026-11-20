from __future__ import annotations

import re
from dataclasses import dataclass

from TranslationPreprocess.c_source_lex import mask_c_non_code


@dataclass(frozen=True)
class CargoDependency:


    name: str
    version: str
    features: tuple[str, ...] = ()

    def toml_line(self) -> str:
        if self.features:
            features = ", ".join(f'"{feature}"' for feature in self.features)
            return (
                f'{self.name} = {{ version = "{self.version}", '
                f"features = [{features}] }}"
            )
        return f'{self.name} = "{self.version}"'


@dataclass(frozen=True)
class LibraryProfile:


    key: str
    detection_names: tuple[str, ...]
    known_functions: frozenset[str]
    supported_functions: frozenset[str]
    function_prefixes: tuple[str, ...]
    cargo_dependencies: tuple[CargoDependency, ...]
    guidance: str


@dataclass(frozen=True)
class LibraryProfileMatch:
    profile: LibraryProfile
    used_functions: tuple[str, ...]
    unsupported_functions: tuple[str, ...]


class UnsupportedLibrarySymbolsError(ValueError):


    def __init__(self, unsupported_by_library: dict[str, set[str]]) -> None:
        self.unsupported_by_library = {
            key: tuple(sorted(values))
            for key, values in sorted(unsupported_by_library.items())
            if values
        }
        details = "; ".join(
            f"{key}: {', '.join(values)}"
            for key, values in self.unsupported_by_library.items()
        )
        super().__init__(
            "native library replacement has no verified mapping for external "
            f"symbols: {details}. No fallback is available."
        )


_ZLIB_KNOWN_FUNCTIONS = frozenset(
    {
        "adler32",
        "adler32_combine",
        "adler32_combine64",
        "adler32_z",
        "compress",
        "compress2",
        "compressBound",
        "crc32",
        "crc32_combine",
        "crc32_combine64",
        "crc32_z",
        "deflate",
        "deflateBound",
        "deflateCopy",
        "deflateEnd",
        "deflateGetDictionary",
        "deflateInit_",
        "deflateInit2_",
        "deflateParams",
        "deflatePending",
        "deflatePrime",
        "deflateReset",
        "deflateResetKeep",
        "deflateSetDictionary",
        "deflateSetHeader",
        "deflateTune",
        "get_crc_table",
        "gzbuffer",
        "gzclearerr",
        "gzclose",
        "gzclose_r",
        "gzclose_w",
        "gzdirect",
        "gzdopen",
        "gzeof",
        "gzerror",
        "gzflush",
        "gzgetc",
        "gzgets",
        "gzoffset",
        "gzopen",
        "gzprintf",
        "gzputc",
        "gzputs",
        "gzread",
        "gzrewind",
        "gzseek",
        "gzsetparams",
        "gztell",
        "gzungetc",
        "gzwrite",
        "inflate",
        "inflateBack",
        "inflateBackEnd",
        "inflateBackInit_",
        "inflateCodesUsed",
        "inflateCopy",
        "inflateEnd",
        "inflateGetDictionary",
        "inflateGetHeader",
        "inflateInit_",
        "inflateInit2_",
        "inflateMark",
        "inflatePrime",
        "inflateReset",
        "inflateReset2",
        "inflateResetKeep",
        "inflateSetDictionary",
        "inflateSync",
        "inflateSyncPoint",
        "inflateUndermine",
        "inflateValidate",
        "uncompress",
        "uncompress2",
        "zError",
        "zlibCompileFlags",
        "zlibVersion",
    }
)

_ZLIB_SUPPORTED_FUNCTIONS = frozenset(
    {
        "compress",
        "compress2",
        "compressBound",
        "deflate",
        "deflateEnd",
        "deflateInit_",
        "deflateInit2_",
        "deflateReset",
        "gzclose",
        "gzclose_r",
        "gzclose_w",
        "gzdopen",
        "gzeof",
        "gzerror",
        "gzflush",
        "gzgetc",
        "gzgets",
        "gzopen",
        "gzputc",
        "gzputs",
        "gzread",
        "gzwrite",
        "inflate",
        "inflateEnd",
        "inflateInit_",
        "inflateInit2_",
        "inflateReset",
        "uncompress",
        "uncompress2",
        "zError",
    }
)

ZLIB_PROFILE = LibraryProfile(
    key="zlib",
    detection_names=(
        "z_stream",
        "z_streamp",
        "gzFile",
        "Bytef",
        "ZLIB_VERSION",
    ),
    known_functions=_ZLIB_KNOWN_FUNCTIONS,
    supported_functions=_ZLIB_SUPPORTED_FUNCTIONS,
    function_prefixes=(),
    cargo_dependencies=(CargoDependency("flate2", "1"),),
    guidance="""
- This entity uses the supported zlib subset. Translate it to the safe `flate2`
  crate; never emit zlib placeholder functions, `libz_sys`, raw FFI, or `unsafe`.
- Use fully-qualified `flate2::...` paths because generated entity code must not
  contain `use` declarations.
- Translate `z_stream` state to `flate2::Compress` or `flate2::Decompress`, and
  translate flush/result codes to `flate2::FlushCompress`,
  `flate2::FlushDecompress`, and `flate2::Status`.
- Translate whole-buffer `compress*`/`uncompress*` calls with zlib encoders and
  decoders over byte slices. Preserve compression level, output bounds, byte
  counts, and error paths.
- Translate `gz*` file operations with `std::fs::File` plus
  `flate2::read::GzDecoder` or `flate2::write::GzEncoder`. Preserve streaming
  reads/writes and finalization errors; do not replace them with fixed values.
- C init/free calls become Rust construction and Drop boundaries. Do not retain
  dummy `z_stream` structs or numeric success stubs.
""".strip(),
)


LIBRARY_PROFILES: tuple[LibraryProfile, ...] = (
    ZLIB_PROFILE,
)


def library_profile_matches_for_source(
    source: str,
    *,
    exclude_functions: frozenset[str] = frozenset(),
) -> tuple[LibraryProfileMatch, ...]:
    masked = mask_c_non_code(source, mask_literals=True)
    calls = _function_calls(masked) - exclude_functions
    matches: list[LibraryProfileMatch] = []

    for profile in LIBRARY_PROFILES:
        used_functions = {
            name
            for name in calls
            if name in profile.known_functions
            or any(name.startswith(prefix) for prefix in profile.function_prefixes)
        }
        detected = bool(used_functions) or any(
            _source_mentions_identifier(masked, name)
            for name in profile.detection_names
        )
        if not detected:
            continue
        unsupported = used_functions - profile.supported_functions
        matches.append(
            LibraryProfileMatch(
                profile=profile,
                used_functions=tuple(sorted(used_functions)),
                unsupported_functions=tuple(sorted(unsupported)),
            )
        )

    return tuple(matches)


def cargo_dependencies_for_matches(
    matches: tuple[LibraryProfileMatch, ...],
) -> tuple[CargoDependency, ...]:
    selected: dict[str, CargoDependency] = {}
    for match in matches:
        for dependency in match.profile.cargo_dependencies:
            previous = selected.get(dependency.name)
            if previous is not None and previous != dependency:
                raise ValueError(
                    f"conflicting Cargo dependency requirements for "
                    f"{dependency.name}: {previous.version} and "
                    f"{dependency.version}"
                )
            selected[dependency.name] = dependency
    return tuple(selected[name] for name in sorted(selected))


def _function_calls(source: str) -> set[str]:
    return set(
        re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", source)
    )


def _source_mentions_identifier(source: str, name: str) -> bool:
    return re.search(rf"\b{re.escape(name)}\b", source) is not None
