from enum import Enum
from ..cimpl import (RESOURCE_UNKNOWN,
                     RESOURCE_ANY,
                     RESOURCE_TOPIC,
                     RESOURCE_GROUP,
                     RESOURCE_BROKER,
                     RESOURCE_PATTERN_UNKNOWN,
                     RESOURCE_PATTERN_ANY,
                     RESOURCE_PATTERN_MATCH,
                     RESOURCE_PATTERN_LITERAL,
                     RESOURCE_PATTERN_PREFIXED)

class ResourceType(Enum):
    """
    Enumerates the different types of Kafka resources.
    """
    UNKNOWN = RESOURCE_UNKNOWN  #: Resource type is not known or not set.
    ANY = RESOURCE_ANY  #: Match any resource, used for lookups.
    TOPIC = RESOURCE_TOPIC  #: Topic resource. Resource name is topic name.
    GROUP = RESOURCE_GROUP  #: Group resource. Resource name is group.id.
    BROKER = RESOURCE_BROKER  #: Broker resource. Resource name is broker id.

    def __lt__(self, other):
        if self.__class__ != other.__class__:
            return NotImplemented
        return self.value < other.value

class ResourcePatternType(Enum):
    """
    Enumerates the different types of Kafka resource patterns.
    """
    UNKNOWN = RESOURCE_PATTERN_UNKNOWN  #: Resource pattern type is not known or not set.
    ANY = RESOURCE_PATTERN_ANY  #: Match any resource, used for lookups.
    MATCH = RESOURCE_PATTERN_MATCH  #: Match: will perform pattern matching
    LITERAL = RESOURCE_PATTERN_LITERAL  #: Literal: A literal resource name
    PREFIXED = RESOURCE_PATTERN_PREFIXED  #: Prefixed: A prefixed resource name

    def __lt__(self, other):
        if self.__class__ != other.__class__:
            return NotImplemented
        return self.value < other.value