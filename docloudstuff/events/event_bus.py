"""
Eventbridge Bus Module
Optionally creates an event archive and schema discoverer
"""

import json
from typing import Optional
import warnings
import pulumi
import pulumi_aws as aws

class Bus:
    """
    Creates an Eventbridge Event Bus
    Optionally creates an Event Archive and or an Event Schema Discoverer

    Args:
        name (str): Unique name that is pre-prended to name resources
        event_archive (Optional[bool]): Optioanally create an Event Archive. Defaults to False.
        archive_days (Optional[int]): If creating an event archive, how many days to retain messages for. Defaults to 7.
        archive_event_pattern (Optional[dict]): An event pattern to use to filter events sent to the archive. Defaults to None.
        schema_discoverer (Optional[bool]): Optionally create a Schema Discoverer for the event bus. Defaults to False.

    Raises:
        ValueError: Days for retention must be greater than or equal to 0
    """

    def __init__(self,
        name: str,
        event_archive: Optional[bool] = False,
        archive_days: Optional[int] = 7,
        archive_event_pattern: Optional[dict] = None,
        schema_discoverer: Optional[bool] = False
    ):

        self.name = name
        self.event_archive = event_archive
        self.archive_days = archive_days
        self.archive_event_pattern = archive_event_pattern
        self.schema_discoverer = schema_discoverer

        if self.event_archive and self.event_archive < 0:
            # If intending to create an event archive check to make sure days is not less than zero
            raise ValueError("Days for Archive Retention must be greater than or equal to 0 (zero).")
        if self.event_archive and self.event_archive == 0:
            # if intending to create an archive, warn if days is equal to zero
            warnings.warn("You enterd 0 (zero) for the amount of days to retain messages in the archive. "
                "This will result in events being stored indefinitely so use caution.", stacklevel=2
            )

        # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventbus/
        bus = aws.cloudwatch.EventBus(f"{self.name}-bus")

        pulumi.export(f"{self.name}-bus-arn", bus.arn)

        if self.event_archive:
            if isinstance(self.archive_event_pattern, dict):
                # Checking to see if the archive pattern was sent as a dict, if so dump to string
                self.archive_event_pattern = json.dumps(self.archive_event_pattern)

            event_archive = aws.cloudwatch.EventArchive(f"{self.name}-event-archive",
                description=f"Archived events from {self.name}-bus",
                event_source_arn=bus.arn,
                retention_days=archive_days,
                event_pattern=self.archive_event_pattern,
                opts = pulumi.ResourceOptions(parent=bus)
            )

            pulumi.export(f"{self.name}-event-archive-arn", event_archive.arn)

        if self.schema_discoverer:
            # https://www.pulumi.com/registry/packages/aws/api-docs/schemas/discoverer/
            bus_schema_discoverer = aws.schemas.Discoverer(f"{self.name}-schema-discoverer",
                source_arn=bus.arn,
                description=f"Schema Discover for the {self.name}-bus",
            )

            pulumi.export(f"{self.name}-schema-discoverer-arn", bus_schema_discoverer.arn)
