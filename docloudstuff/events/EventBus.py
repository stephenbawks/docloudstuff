from typing import Optional
import pulumi
import pulumi_aws as aws


class Bus:
    """

    """

    def __init__(self, name: str, description: Optional [str] = None, event_bus_name: Optional[str] = "default"):
        self.name = name
        self.description = description
        self.event_bus_name = event_bus_name

