# Copyright 2022 Confluent Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from enum import Enum
import functools
from .. import cimpl as _cimpl
from ._resource import ResourceType, ResourcePatternType

try:
    string_type = basestring  # noqa
except NameError:
    string_type = str


class AclOperation(Enum):
    """
    Enumerates the different types of ACL operation.
    """
    UNKNOWN = _cimpl.ACL_OPERATION_UNKNOWN  # : Unknown
    ANY = _cimpl.ACL_OPERATION_ANY  # : In a filter, matches any AclOperation
    ALL = _cimpl.ACL_OPERATION_ALL  # : ALL operation
    READ = _cimpl.ACL_OPERATION_READ  # : READ operation
    WRITE = _cimpl.ACL_OPERATION_WRITE  # : WRITE operation
    CREATE = _cimpl.ACL_OPERATION_CREATE  # : CREATE operation
    DELETE = _cimpl.ACL_OPERATION_DELETE  # : DELETE operation
    ALTER = _cimpl.ACL_OPERATION_ALTER  # : ALTER operation
    DESCRIBE = _cimpl.ACL_OPERATION_DESCRIBE  # : DESCRIBE operation
    CLUSTER_ACTION = _cimpl.ACL_OPERATION_CLUSTER_ACTION  # : CLUSTER_ACTION operation
    DESCRIBE_CONFIGS = _cimpl.ACL_OPERATION_DESCRIBE_CONFIGS  # : DESCRIBE_CONFIGS operation
    ALTER_CONFIGS = _cimpl.ACL_OPERATION_ALTER_CONFIGS  # : ALTER_CONFIGS  operation
    IDEMPOTENT_WRITE = _cimpl.ACL_OPERATION_IDEMPOTENT_WRITE  # : IDEMPOTENT_WRITE operation

    def __lt__(self, other):
        if self.__class__ != other.__class__:
            return NotImplemented
        return self.value < other.value


class AclPermissionType(Enum):
    """
    Enumerates the different types of ACL permission types.
    """
    UNKNOWN = _cimpl.ACL_PERMISSION_TYPE_UNKNOWN  # : Unknown
    ANY = _cimpl.ACL_PERMISSION_TYPE_ANY  # : In a filter, matches any AclPermissionType
    DENY = _cimpl.ACL_PERMISSION_TYPE_DENY  # : Disallows access
    ALLOW = _cimpl.ACL_PERMISSION_TYPE_ALLOW  # : Grants access

    def __lt__(self, other):
        if self.__class__ != other.__class__:
            return NotImplemented
        return self.value < other.value


@functools.total_ordering
class AclBinding(object):
    """
    Represents an ACL binding that specify the operation and permission type for a specific principal
    over one or more resources of the same type. Used by create_acls, returned by describe_acls and delete_acls.

    Parameters
    ----------
    restype : `ResourceType`
        The resource type.
    name : `str`
        The resource name, which depends on the resource type. For RESOURCE_BROKER, the resource name is the broker id.
    resource_pattern_type : `ResourcePatternType`
        The resource pattern, relative to the name.
    principal : `str`
        The principal this AclBinding refers to.
    host : `str`
        The host that the call is allowed to come from.
    operation: `AclOperation`
        The operation/s specified by this binding.
    permission_type: `AclPermissionType`
        The permission type for the specified operation.
    """

    def __init__(self, restype, name,
                 resource_pattern_type, principal, host,
                 operation, permission_type):
        """
        :param ResourceType restype: Resource type.
        :param str name: The resource name, which depends on restype.
                         For RESOURCE_BROKER, the resource name is the broker id.
        :param ResourcePatternType resource_pattern_type: The resource pattern, relative to the name.
        :param str principal: The principal this AclBinding refers to.
        :param str host: The host that the call is allowed to come from.
        :param AclOperation operation: The operation/s specified by this binding.
        :param AclPermissionType The permission type for the specified operation.
        """
        self.restype = restype
        self.name = name
        self.resource_pattern_type = resource_pattern_type
        self.principal = principal
        self.host = host
        self.operation = operation
        self.permission_type = permission_type
        self._convert_args()
        # for the C code
        self.restype_int = int(self.restype.value)
        self.resource_pattern_type_int = int(self.resource_pattern_type.value)
        self.operation_int = int(self.operation.value)
        self.permission_type_int = int(self.permission_type.value)

    def _check_not_none(self, vars_to_check):
        for param in vars_to_check:
            if getattr(self, param) is None:
                raise ValueError("Expected %s to be not None" % (param,))

    def _check_is_string(self, vars_to_check):
        for param in vars_to_check:
            param_value = getattr(self, param)
            if param_value is not None and not isinstance(param_value, string_type):
                raise TypeError("Expected %s to be a string" % (param,))

    def _convert_to_enum(self, val, enum_clazz):
        if type(val) == str:
            # Allow it to be specified as case-insensitive string, for convenience.
            try:
                val = enum_clazz[val.upper()]
            except KeyError:
                raise ValueError("Unknown value \"%s\": should be a %s" % (val, enum_clazz.__name__))

        elif type(val) == int:
            # The C-code passes restype as an int, convert to enum.
            val = enum_clazz(val)

        elif type(val) != enum_clazz:
            raise TypeError("Unknown value \"%s\": should be a %s" % (val, enum_clazz.__name__))

        return val

    def _convert_enums(self):
        self.restype = self._convert_to_enum(self.restype, ResourceType)
        self.resource_pattern_type = self._convert_to_enum(self.resource_pattern_type, ResourcePatternType)
        self.operation = self._convert_to_enum(self.operation, AclOperation)
        self.permission_type = self._convert_to_enum(self.permission_type, AclPermissionType)

    def _check_forbidden_enums(self, forbidden_enums):
        for k, v in forbidden_enums.items():
            enum_value = getattr(self, k)
            if enum_value in v:
                raise ValueError("Cannot use enum %s, value %s in this class" % (k, enum_value.name))

    def _not_none_args(self):
        return ["restype", "name", "resource_pattern_type",
                "principal", "host", "operation", "permission_type"]

    def _string_args(self):
        return ["name", "principal", "host"]

    def _forbidden_enums(self):
        return {
            "restype": [ResourceType.ANY],
            "resource_pattern_type": [ResourcePatternType.ANY,
                                      ResourcePatternType.MATCH],
            "operation": [AclOperation.ANY],
            "permission_type": [AclPermissionType.ANY]
        }

    def _convert_args(self):
        not_none_args = self._not_none_args()
        string_args = self._string_args()
        forbidden_enums = self._forbidden_enums()
        self._check_not_none(not_none_args)
        self._check_is_string(string_args)
        self._convert_enums()
        self._check_forbidden_enums(forbidden_enums)

    def __repr__(self):
        type_name = type(self).__name__
        return "%s(%s,%s,%s,%s,%s,%s,%s)" % ((type_name,) + self._to_tuple())

    def _to_tuple(self):
        return (self.restype, self.name, self.resource_pattern_type,
                self.principal, self.host, self.operation,
                self.permission_type)

    def __hash__(self):
        return hash(self._to_tuple())

    def __lt__(self, other):
        if self.__class__ != other.__class__:
            return NotImplemented
        return self._to_tuple() < other._to_tuple()

    def __eq__(self, other):
        if self.__class__ != other.__class__:
            return NotImplemented
        return self._to_tuple() == other._to_tuple()


class AclBindingFilter(AclBinding):
    """
    Represents an ACL binding filter used to return a list of ACL bindings matching some or all of its attributes.
    Used by describe_acls and delete_acls.

    Parameters
    ----------
    restype : `ResourceType`
        The resource type, or ResourceType.ANY to match any value.
    name : `str`
        The resource name to match.
        None matches any value.
    resource_pattern_type : `ResourcePatternType`
        The resource pattern, ResourcePatternType.ANY to match any value or
        ResourcePatternType.MATCH to perform pattern matching.
    principal : `str`
        The principal to match, or None to match any value.
    host : `str`
        The host to match, or None to match any value.
    operation: `AclOperation`
        The operation to match or AclOperation.ANY to match any value.
    permission_type: `AclPermissionType`
        The permission type to match or AclPermissionType.ANY to match any value.
    """

    def _not_none_args(self):
        return ["restype", "resource_pattern_type",
                "operation", "permission_type"]

    def _forbidden_enums(self):
        return {
            "restype": [ResourceType.UNKNOWN],
            "resource_pattern_type": [ResourcePatternType.UNKNOWN],
            "operation": [AclOperation.UNKNOWN],
            "permission_type": [AclPermissionType.UNKNOWN]
        }
