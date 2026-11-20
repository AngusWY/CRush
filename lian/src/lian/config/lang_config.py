from dataclasses import dataclass
import os
from lian.config.config import LANG_SO_DIR
from lian.lang import (
    abc_parser,
    c_parser,
    csharp_parser,
    go_parser,
    java_parser,
    javascript_parser,
    python_parser,
    ruby_parser,
    php_parser,
    llvm_parser,
    smali_parser,
    typescript_parser,
)
import platform
from lian.util import util

@dataclass
class LangConfig:
    name     : str
    parser   : object
    extension: list     = None
    so_path  : str      = ""


LANG_TABLE = [
    LangConfig(name = "abc", extension = [".txt"], parser = abc_parser.Parser),
    LangConfig(name = "c", extension = [".c", ".h", ".i",], parser = c_parser.Parser),
    LangConfig(name = "cpp", extension = [".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".ii"], parser = c_parser.Parser),
    LangConfig(name = "csharp", extension = [".cs"], parser = csharp_parser.Parser),
    LangConfig(name = "go", extension = [".go"], parser = go_parser.Parser),
    LangConfig(name = "java", extension = [".java"], parser = java_parser.Parser),
    LangConfig(name = "javascript", extension = [".js"], parser = javascript_parser.Parser),
    LangConfig(name = "python", extension = [".py"], parser = python_parser.Parser),
    LangConfig(name = "php", extension = [".php"], parser = php_parser.Parser),
    LangConfig(name = "ruby", extension = [".rb"], parser = ruby_parser.Parser),
    LangConfig(name = "smali", extension = [".smali"], parser = smali_parser.Parser),
    LangConfig(name = "typescript", extension = [".ts", ".tsx"], parser = typescript_parser.Parser),
    LangConfig(name = "llvm", extension = [".ll"], parser = llvm_parser.Parser),
]

def get_platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()


    if system == "linux":
        if machine in ("x86_64", "amd64"):
            return "linux_x86_64"
        if machine in ("i386", "i686"):
            return "linux_x86_32"






    if system == "windows":
        if machine in ("x86_64", "amd64"):
            return "windows_x86_64"
        if machine in ("x86", "i386", "i686"):
            return "windows_x86_32"


    if system == "darwin":
        if machine == "x86_64":
            return "darwin_x86_64"
        if machine == "arm64":
            return "darwin_arm64"


    return "generic"


for lang in LANG_TABLE:

    lang.so_path = os.path.join(LANG_SO_DIR, get_platform_key(), f"{lang.name}.so")




LANG_EXTENSIONS = {}
EXTENSIONS_LANG = {}
def update_lang_extensions(lang_table, lang_list):
    global LANG_EXTENSIONS
    global EXTENSIONS_LANG

    for line in lang_table:
        LANG_EXTENSIONS[line.name] = line.extension


    if "c" in lang_list:
        if ".h" in LANG_EXTENSIONS.get("cpp", []):
            LANG_EXTENSIONS["cpp"].remove(".h")
    elif "cpp" in lang_list:
        if ".h" in LANG_EXTENSIONS.get("c", []):
            LANG_EXTENSIONS["c"].remove(".h")

    for lang, exts in LANG_EXTENSIONS.items():
        for each_ext in exts:
            if each_ext not in EXTENSIONS_LANG:
                EXTENSIONS_LANG[each_ext] = lang
