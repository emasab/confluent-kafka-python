"""
Kafka admin client: create, view, alter, and delete topics and resources.
"""
import concurrent.futures
from ._config import ConfigSource, \
                     ConfigEntry, \
                     ConfigResource
from ._resource import ResourceType, \
                       ResourcePatternType
from ._acl import AclOperation, \
                  AclPermissionType, \
                  AclBinding, \
                  AclBindingFilter
from ..cimpl import (KafkaException,
                     KafkaError,
                     _AdminClientImpl,
                     NewTopic,
                     NewPartitions)

class AdminClient (_AdminClientImpl):
    """
    AdminClient provides admin operations for Kafka brokers, topics, groups,
    and other resource types supported by the broker.

    The Admin API methods are asynchronous and return a dict of
    concurrent.futures.Future objects keyed by the entity.
    The entity is a topic name for create_topics(), delete_topics(), create_partitions(),
    and a ConfigResource for alter_configs() and describe_configs().

    All the futures for a single API call will currently finish/fail at
    the same time (backed by the same protocol request), but this might
    change in future versions of the client.

    See examples/adminapi.py for example usage.

    For more information see the `Java Admin API documentation
    <https://docs.confluent.io/current/clients/javadocs/org/apache/kafka/clients/admin/package-frame.html>`_.

    Requires broker version v0.11.0.0 or later.
    """
    def __init__(self, conf):
        """
        Create a new AdminClient using the provided configuration dictionary.

        The AdminClient is a standard Kafka protocol client, supporting
        the standard librdkafka configuration properties as specified at
        https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md

        At least 'bootstrap.servers' should be configured.
        """
        super(AdminClient, self).__init__(conf)

    @staticmethod
    def _make_topics_result(f, futmap):
        """
        Map per-topic results to per-topic futures in futmap.
        The result value of each (successful) future is None.
        """
        try:
            result = f.result()
            for topic, error in result.items():
                fut = futmap.get(topic, None)
                if fut is None:
                    raise RuntimeError("Topic {} not found in future-map: {}".format(topic, futmap))

                if error is not None:
                    # Topic-level exception
                    fut.set_exception(KafkaException(error))
                else:
                    # Topic-level success
                    fut.set_result(None)
        except Exception as e:
            # Request-level exception, raise the same for all topics
            for topic, fut in futmap.items():
                fut.set_exception(e)

    @staticmethod
    def _make_resource_result(f, futmap):
        """
        Map per-resource results to per-resource futures in futmap.
        The result value of each (successful) future is a ConfigResource.
        """
        try:
            result = f.result()
            for resource, configs in result.items():
                fut = futmap.get(resource, None)
                if fut is None:
                    raise RuntimeError("Resource {} not found in future-map: {}".format(resource, futmap))
                if resource.error is not None:
                    # Resource-level exception
                    fut.set_exception(KafkaException(resource.error))
                else:
                    # Resource-level success
                    # configs will be a dict for describe_configs()
                    # and None for alter_configs()
                    fut.set_result(configs)
        except Exception as e:
            # Request-level exception, raise the same for all resources
            for resource, fut in futmap.items():
                fut.set_exception(e)

    @staticmethod
    def _make_create_acls_result(f, futmap):
        """
        TODO:
        """
        try:
            results = f.result()
            futmap_values = list(futmap.values())
            len_results = len(results)
            len_futures = len(futmap_values)
            if len_results != len_futures:
                raise RuntimeError("Results length {} is different from future-map length {}".format(len_results, len_futures))
            for i, result in enumerate(results):
                fut = futmap_values[i]
                if result is not None:
                    fut.set_exception(KafkaException(result))
                else:
                    fut.set_result(result)
        except Exception as e:
            # Request-level exception, raise the same for all AclBindings
            for resource, fut in futmap.items():
                fut.set_exception(e)


    @staticmethod
    def _make_delete_acls_result(f, futmap):
        """
        TODO:
        """
        try:
            results = f.result()
            futmap_values = list(futmap.values())
            len_results = len(results)
            len_futures = len(futmap_values)
            if len_results != len_futures:
                raise RuntimeError("Results length {} is different from future-map length {}".format(len_results, len_futures))
            for i, result in enumerate(results):
                fut = futmap_values[i]
                if isinstance(result,KafkaError):
                    # AclBinding exception
                    fut.set_exception(KafkaException(result))
                else:
                    fut.set_result(result)
        except Exception as e:
            # Request-level exception, raise the same for all AclBindings
            for resource, fut in futmap.items():
                fut.set_exception(e)


    @staticmethod
    def _make_futures(futmap_keys, class_check, make_result_fn):
        """
        Create futures and a futuremap for the keys in futmap_keys,
        and create a request-level future to be bassed to the C API.
        """
        futmap = {}
        for key in futmap_keys:
            if class_check is not None and not isinstance(key, class_check):
                raise ValueError("Expected list of {}".format(repr(class_check)))
            futmap[key] = concurrent.futures.Future()
            if not futmap[key].set_running_or_notify_cancel():
                raise RuntimeError("Future was cancelled prematurely")

        # Create an internal future for the entire request,
        # this future will trigger _make_..._result() and set result/exception
        # per topic,future in futmap.
        f = concurrent.futures.Future()
        f.add_done_callback(lambda f: make_result_fn(f, futmap))

        if not f.set_running_or_notify_cancel():
            raise RuntimeError("Future was cancelled prematurely")

        return f, futmap

    def create_topics(self, new_topics, **kwargs):
        """
        Create one or more new topics.

        :param list(NewTopic) new_topics: A list of specifictions (NewTopic) for
                  the topics that should be created.
        :param float operation_timeout: The operation timeout in seconds,
                  controlling how long the CreateTopics request will block
                  on the broker waiting for the topic creation to propagate
                  in the cluster. A value of 0 returns immediately. Default: 0
        :param float request_timeout: The overall request timeout in seconds,
                  including broker lookup, request transmission, operation time
                  on broker, and response. Default: `socket.timeout.ms*1000.0`
        :param bool validate_only: If true, the request is only validated
                  without creating the topic. Default: False

        :returns: A dict of futures for each topic, keyed by the topic name.
                  The future result() method returns None.

        :rtype: dict(<topic_name, future>)

        :raises KafkaException: Operation failed locally or on broker.
        :raises TypeException: Invalid input.
        :raises ValueException: Invalid input.
        """

        f, futmap = AdminClient._make_futures([x.topic for x in new_topics],
                                              None,
                                              AdminClient._make_topics_result)

        super(AdminClient, self).create_topics(new_topics, f, **kwargs)

        return futmap

    def delete_topics(self, topics, **kwargs):
        """
        Delete one or more topics.

        :param list(str) topics: A list of topics to mark for deletion.
        :param float operation_timeout: The operation timeout in seconds,
                  controlling how long the DeleteTopics request will block
                  on the broker waiting for the topic deletion to propagate
                  in the cluster. A value of 0 returns immediately. Default: 0
        :param float request_timeout: The overall request timeout in seconds,
                  including broker lookup, request transmission, operation time
                  on broker, and response. Default: `socket.timeout.ms*1000.0`

        :returns: A dict of futures for each topic, keyed by the topic name.
                  The future result() method returns None.

        :rtype: dict(<topic_name, future>)

        :raises KafkaException: Operation failed locally or on broker.
        :raises TypeException: Invalid input.
        :raises ValueException: Invalid input.
        """

        f, futmap = AdminClient._make_futures(topics, None,
                                              AdminClient._make_topics_result)

        super(AdminClient, self).delete_topics(topics, f, **kwargs)

        return futmap

    def list_topics(self, **kwargs):

        return super(AdminClient, self).list_topics(**kwargs)

    def list_groups(self, **kwargs):

        return super(AdminClient, self).list_groups(**kwargs)

    def create_partitions(self, new_partitions, **kwargs):
        """
        Create additional partitions for the given topics.

        :param list(NewPartitions) new_partitions: New partitions to be created.
        :param float operation_timeout: The operation timeout in seconds,
                  controlling how long the CreatePartitions request will block
                  on the broker waiting for the partition creation to propagate
                  in the cluster. A value of 0 returns immediately. Default: 0
        :param float request_timeout: The overall request timeout in seconds,
                  including broker lookup, request transmission, operation time
                  on broker, and response. Default: `socket.timeout.ms*1000.0`
        :param bool validate_only: If true, the request is only validated
                  without creating the partitions. Default: False

        :returns: A dict of futures for each topic, keyed by the topic name.
                  The future result() method returns None.

        :rtype: dict(<topic_name, future>)

        :raises KafkaException: Operation failed locally or on broker.
        :raises TypeException: Invalid input.
        :raises ValueException: Invalid input.
        """

        f, futmap = AdminClient._make_futures([x.topic for x in new_partitions],
                                              None,
                                              AdminClient._make_topics_result)

        super(AdminClient, self).create_partitions(new_partitions, f, **kwargs)

        return futmap

    def describe_configs(self, resources, **kwargs):
        """
        Get the configuration of the specified resources.

        :warning: Multiple resources and resource types may be requested,
                  but at most one resource of type RESOURCE_BROKER is allowed
                  per call since these resource requests must be sent to the
                  broker specified in the resource.

        :param list(ConfigResource) resources: Resources to get the configuration for.
        :param float request_timeout: The overall request timeout in seconds,
                  including broker lookup, request transmission, operation time
                  on broker, and response. Default: `socket.timeout.ms*1000.0`

        :returns: A dict of futures for each resource, keyed by the ConfigResource.
                  The type of the value returned by the future result() method is
                  dict(<configname, ConfigEntry>).

        :rtype: dict(<ConfigResource, future>)

        :raises KafkaException: Operation failed locally or on broker.
        :raises TypeException: Invalid input.
        :raises ValueException: Invalid input.
        """

        f, futmap = AdminClient._make_futures(resources, ConfigResource,
                                              AdminClient._make_resource_result)

        super(AdminClient, self).describe_configs(resources, f, **kwargs)

        return futmap

    def alter_configs(self, resources, **kwargs):
        """
        Update configuration properties for the specified resources.
        Updates are not transactional so they may succeed for a subset
        of the provided resources while the others fail.
        The configuration for a particular resource is updated atomically,
        replacing the specified values while reverting unspecified configuration
        entries to their default values.

        :warning: alter_configs() will replace all existing configuration for
                  the provided resources with the new configuration given,
                  reverting all other configuration for the resource back
                  to their default values.

        :warning: Multiple resources and resource types may be specified,
                  but at most one resource of type RESOURCE_BROKER is allowed
                  per call since these resource requests must be sent to the
                  broker specified in the resource.

        :param list(ConfigResource) resources: Resources to update configuration of.
        :param float request_timeout: The overall request timeout in seconds,
                  including broker lookup, request transmission, operation time
                  on broker, and response. Default: `socket.timeout.ms*1000.0`.
        :param bool validate_only: If true, the request is validated only,
                  without altering the configuration. Default: False

        :returns: A dict of futures for each resource, keyed by the ConfigResource.
                  The future result() method returns None.

        :rtype: dict(<ConfigResource, future>)

        :raises KafkaException: Operation failed locally or on broker.
        :raises TypeException: Invalid input.
        :raises ValueException: Invalid input.
        """

        f, futmap = AdminClient._make_futures(resources, ConfigResource,
                                              AdminClient._make_resource_result)

        super(AdminClient, self).alter_configs(resources, f, **kwargs)

        return futmap

    def create_acls(self, acls, **kwargs):
        """
        TODO:
        """

        f, futmap = AdminClient._make_futures(acls, AclBinding,
                                              AdminClient._make_create_acls_result)

        super(AdminClient, self).create_acls(acls, f, **kwargs)

        return futmap

    def delete_acls(self, acls, **kwargs):
        """
        TODO:
        """

        f, futmap = AdminClient._make_futures(acls, AclBindingFilter,
                                              AdminClient._make_delete_acls_result)

        super(AdminClient, self).delete_acls(acls, f, **kwargs)

        return futmap


class ClusterMetadata (object):
    """
    Provides information about the Kafka cluster, brokers, and topics.
    Returned by list_topics().

    This class is typically not user instantiated.
    """
    def __init__(self):
        self.cluster_id = None
        """Cluster id string, if supported by the broker, else None."""
        self.controller_id = -1
        """Current controller broker id, or -1."""
        self.brokers = {}
        """Map of brokers indexed by the broker id (int). Value is a BrokerMetadata object."""
        self.topics = {}
        """Map of topics indexed by the topic name. Value is a TopicMetadata object."""
        self.orig_broker_id = -1
        """The broker this metadata originated from."""
        self.orig_broker_name = None
        """The broker name/address this metadata originated from."""

    def __repr__(self):
        return "ClusterMetadata({})".format(self.cluster_id)

    def __str__(self):
        return str(self.cluster_id)


class BrokerMetadata (object):
    """
    Provides information about a Kafka broker.

    This class is typically not user instantiated.
    """
    def __init__(self):
        self.id = -1
        """Broker id"""
        self.host = None
        """Broker hostname"""
        self.port = -1
        """Broker port"""

    def __repr__(self):
        return "BrokerMetadata({}, {}:{})".format(self.id, self.host, self.port)

    def __str__(self):
        return "{}:{}/{}".format(self.host, self.port, self.id)


class TopicMetadata (object):
    """
    Provides information about a Kafka topic.

    This class is typically not user instantiated.
    """
    # The dash in "-topic" and "-error" is needed to circumvent a
    # Sphinx issue where it tries to reference the same instance variable
    # on other classes which raises a warning/error.
    def __init__(self):
        self.topic = None
        """Topic name"""
        self.partitions = {}
        """Map of partitions indexed by partition id. Value is a PartitionMetadata object."""
        self.error = None
        """Topic error, or None. Value is a KafkaError object."""

    def __repr__(self):
        if self.error is not None:
            return "TopicMetadata({}, {} partitions, {})".format(self.topic, len(self.partitions), self.error)
        else:
            return "TopicMetadata({}, {} partitions)".format(self.topic, len(self.partitions))

    def __str__(self):
        return self.topic


class PartitionMetadata (object):
    """
    Provides information about a Kafka partition.

    This class is typically not user instantiated.

    :warning: Depending on cluster state the broker ids referenced in
              leader, replicas and ISRs may temporarily not be reported
              in ClusterMetadata.brokers. Always check the availability
              of a broker id in the brokers dict.
    """
    def __init__(self):
        self.id = -1
        """Partition id."""
        self.leader = -1
        """Current leader broker for this partition, or -1."""
        self.replicas = []
        """List of replica broker ids for this partition."""
        self.isrs = []
        """List of in-sync-replica broker ids for this partition."""
        self.error = None
        """Partition error, or None. Value is a KafkaError object."""

    def __repr__(self):
        if self.error is not None:
            return "PartitionMetadata({}, {})".format(self.id, self.error)
        else:
            return "PartitionMetadata({})".format(self.id)

    def __str__(self):
        return "{}".format(self.id)


class GroupMember(object):
    """Provides information about a group member.

    For more information on the metadata format, refer to:
    `A Guide To The Kafka Protocol <https://cwiki.apache.org/confluence/display/KAFKA/A+Guide+To+The+Kafka+Protocol#AGuideToTheKafkaProtocol-GroupMembershipAPI>`_.

    This class is typically not user instantiated.
    """  # noqa: E501
    def __init__(self,):
        self.id = None
        """Member id (generated by broker)."""
        self.client_id = None
        """Client id."""
        self.client_host = None
        """Client hostname."""
        self.metadata = None
        """Member metadata(binary), format depends on protocol type."""
        self.assignment = None
        """Member assignment(binary), format depends on protocol type."""


class GroupMetadata(object):
    """GroupMetadata provides information about a Kafka consumer group

    This class is typically not user instantiated.
    """
    def __init__(self):
        self.broker = None
        """Originating broker metadata."""
        self.id = None
        """Group name."""
        self.error = None
        """Broker-originated error, or None. Value is a KafkaError object."""
        self.state = None
        """Group state."""
        self.protocol_type = None
        """Group protocol type."""
        self.protocol = None
        """Group protocol."""
        self.members = []
        """Group members."""

    def __repr__(self):
        if self.error is not None:
            return "GroupMetadata({}, {})".format(self.id, self.error)
        else:
            return "GroupMetadata({})".format(self.id)

    def __str__(self):
        return self.id
