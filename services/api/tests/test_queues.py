"""The SQS adapter's error mapping, without SQS."""

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from sft.workers.queues import _queue_error


def client_error(code: str, status: int) -> ClientError:
    return ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}},
        "SendMessageBatch",
    )


@pytest.mark.parametrize(
    ("code", "status", "sender_fault"),
    [
        ("BatchRequestTooLong", 400, True),
        ("InvalidAttributeValue", 400, True),
        ("AWS.SimpleQueueService.NonExistentQueue", 400, False),
        ("QueueDoesNotExist", 400, False),
        ("RequestThrottled", 400, False),
        ("ThrottlingException", 400, False),
        ("InternalError", 500, False),
    ],
)
def test_only_a_refusal_of_something_in_the_batch_is_a_sender_fault(
    code: str, status: int, sender_fault: bool
) -> None:
    error = _queue_error(client_error(code, status))
    assert (error.code, error.sender_fault) == (code, sender_fault)


def test_a_connection_error_is_no_sender_fault() -> None:
    error = _queue_error(EndpointConnectionError(endpoint_url="http://sqs"))
    assert (error.code, error.sender_fault) == ("EndpointConnectionError", False)
