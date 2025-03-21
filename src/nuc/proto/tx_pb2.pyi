from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import (
    ClassVar as _ClassVar,
    Iterable as _Iterable,
    Mapping as _Mapping,
    Optional as _Optional,
    Union as _Union,
)

DESCRIPTOR: _descriptor.FileDescriptor

class MsgPayFor(_message.Message):
    __slots__ = ("resource", "from_address", "amount")
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    FROM_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    resource: bytes
    from_address: str
    amount: _containers.RepeatedCompositeFieldContainer[Amount]
    def __init__(
        self,
        resource: _Optional[bytes] = ...,
        from_address: _Optional[str] = ...,
        amount: _Optional[_Iterable[_Union[Amount, _Mapping]]] = ...,
    ) -> None: ...

class Amount(_message.Message):
    __slots__ = ("denom", "amount")
    DENOM_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    denom: str
    amount: str
    def __init__(
        self, denom: _Optional[str] = ..., amount: _Optional[str] = ...
    ) -> None: ...
