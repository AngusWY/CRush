

import dataclasses
from lian.config import config
from lian.config.constants import (
    RULE_KIND
)

@dataclasses.dataclass
class Rule:

    rule_id:int             = -1

    kind: int               = RULE_KIND.RULE

    lang: str               = config.ANY_LANG
    class_name: str         = ""
    method_name: str        = ""
    args: str               = ""

    src: list               = dataclasses.field(default_factory=list)
    dst: list               = dataclasses.field(default_factory=list)
    unset:bool              = False

    mock_path: str          = ""
    mock_id: int            = -1

    model_method: object    = None

    def __repr__(self):
        return f"Rule(rule_id={self.rule_id}, kind={self.kind}, lang={self.lang}, class_name={self.class_name}, method_name={self.method_name}, args={self.args}, src={self.src}, dst={self.dst}, unset={self.unset}, mock_path={self.mock_path}, mock_id={self.mock_id}, model_method={self.model_method})"

    def to_dict(self):
        return {
            "rule_id"             : self.rule_id,
            "kind"                : self.kind,
            "lang"                : self.lang,
            "class_name"          : self.class_name,
            "method_name"         : self.method_name,
            "args"                : self.args,
            "src"                 : self.src,
            "dst"                 : self.dst,
            "unset"               : self.unset,
            "mock_path"           : self.mock_path,
            "mock_id"             : self.mock_id,
            "model_method"        : self.model_method
        }



