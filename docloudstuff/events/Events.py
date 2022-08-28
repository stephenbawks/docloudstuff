"""
Events module
"""
from typing import Optional
import pulumi
import pulumi_aws as aws


class Events:
    """
    Base Events class

    Args:
        name (str): unique name for the object
        description (str): Optional - Description of the events object
        event_bus_name (str): Optional - Name of the event bus.  If none, will specify the default bus.

    Examples:
    >>> my_service = Events(name="myAwesomeService", description="Distributes Awesome", event_bus_name="event-bus-to-somewhere"
    """

    def __init__(self, name: str, description: Optional [str] = None, event_bus_name: Optional[str] = "default"):
        self.name = name
        self.description = description
        self.event_bus_name = event_bus_name


class Rule(Events):
    """
    Rules class
    Inherits the base Events class

    Args:
        event_pattern (str): Event Pattern
    """
    def __init__(self, name: str, event_pattern: str, description: Optional[str] = None, event_bus_name: Optional[str] = "default"):
        super().__init__(name, description, event_bus_name)
        self.event_pattern = event_pattern

        aws.cloudwatch.EventRule(
            f"{self.name}-EventRule",
            name = self.name,
            description = self.description,
            event_bus_name = self.event_bus_name,
            is_enabled = True,
            event_pattern = self.event_pattern
        )

class Target(Events):
    """
    Target class
    Inherits the base Events class

    Args:
        rule_name (str): Unique name for the Event Rule
        target_arn (str): AWS ARN that the Event Rule will target

    Examples:

    """
    def __init__(self, name: str, rule_name: str, target_arn: str, description: Optional[str] = None, event_bus_name: Optional[str] = "default"):
        super().__init__(name, description, event_bus_name)
        self.rule_name = rule_name
        self.target_arn =  target_arn
        self.resource_name = aws.get_arn(arn=target_arn).resource
        self.resource_type = aws.get_arn(arn=target_arn).service

        # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
        aws.cloudwatch.EventTarget(
            f"{self.name}RuleTarget",
            arn=self.target_arn,
            event_bus_name=self.event_bus_name,
            rule=self.rule_name
        )

class RuleTarget(Events):
    """
        Creates an Eventbridge Rule and attaches a target
        Adds addtional resources depending on the target

    URLs:
        https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arns-syntax
        arn:partition:service:region:account-id:resource-id
        arn:partition:service:region:account-id:resource-type/resource-id

    Args:
        Events (_type_): _description_
    """
    def __init__(self,
        name: str,
        event_pattern: str,
        target_arn: str,
        description: Optional[str] = None,
        event_bus_name: Optional[str] = "default",
        optional_log_group: Optional[bool] = False,
        input_paths: Optional[dict[str, str]] = None,
        input_template: Optional[str] = None,
        max_retry_attempts: Optional[int] = 185,
        max_event_age_seconds: Optional[int] = 86400
        ):

        super().__init__(name, description, event_bus_name)
        self.event_pattern = event_pattern
        self.target_arn =  target_arn
        self.resource_name = aws.get_arn(arn=target_arn).resource
        self.resource_type = aws.get_arn(arn=target_arn).service
        self.log_group = optional_log_group
        self.input_paths = input_paths
        self.input_template = input_template
        self.max_retry_attempts = max_retry_attempts
        self.max_event_age_seconds = max_event_age_seconds


        # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventrule/
        rule = aws.cloudwatch.EventRule(
            f"{self.name}-EventRule",
            name = self.name,
            description = self.description,
            event_bus_name = self.event_bus_name,
            is_enabled = True,
            event_pattern = self.event_pattern
        )

        pulumi.export(f"{self.name}-rule-arn", rule.arn)

        # If the event is being transformed, there are two variables that are required
        # `input_paths` and `input_transformer`
        if self.input_paths and self.input_template:
            input_transformer = aws.cloudwatch.EventTargetInputTransformerArgs(
                input_paths = input_paths,
                input_template = input_template
            )
        else:
            input_transformer = None


        def general_event():
            # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
            aws.cloudwatch.EventTarget(
                f"{self.name}-RuleTarget",
                arn = self.target_arn,
                event_bus_name = self.event_bus_name,
                rule = rule.name,
                input_transformer = input_transformer,
                retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                    maximum_event_age_in_seconds = self.max_event_age_seconds,
                    maximum_retry_attempts = self.max_retry_attempts
                ),
                opts = pulumi.ResourceOptions(parent=rule)
            )

        def create_lambda_event():
            # Additional Logic for Lambda as a Target
            print("Lambda Target --> Adding Lambda Invoke Permission")

            # https://www.pulumi.com/registry/packages/aws/api-docs/lambda/permission/
            aws.lambda_.Permission(
                f"{self.name}-LambdaPermission",
                action = "lambda:InvokeFunction",
                function = self.resource_name,
                principal = "events.amazonaws.com",
                source_arn = rule.arn,
                opts = pulumi.ResourceOptions(parent=rule)
            )

            aws.cloudwatch.EventTarget(
                f"{self.name}-RuleTarget",
                arn = self.target_arn,
                event_bus_name = self.event_bus_name,
                rule = rule.arn,
                input_transformer = input_transformer,
                retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                    maximum_event_age_in_seconds = self.max_event_age_seconds,
                    maximum_retry_attempts = self.max_retry_attempts
                ),
                opts = pulumi.ResourceOptions(parent=rule)
            )

        def create_events_event():

            # This could be an API Destination or trying to send to another Eventbridge
            if self.resource_name.startswith("event-bus"):
                # Additional Logic for another Event Bus as a Target
                print("Event Bus Target --> Creating IAM Role")

                assume_role_policy = aws.iam.get_policy_document(statements=[
                    aws.iam.GetPolicyDocumentStatementArgs(
                        actions = ["sts:AssumeRole"],
                        principals = [aws.iam.GetPolicyDocumentStatementPrincipalArgs(
                            type = "Service",
                            identifiers = ["events.amazonaws.com"],
                        )],
                    )]
                )

                # https://www.pulumi.com/registry/packages/aws/api-docs/iam/getpolicydocument/
                event_bus_policy = aws.iam.get_policy_document(
                    statements = [
                        aws.iam.GetPolicyDocumentStatementArgs(
                            actions = [
                                "events:PutEvents"
                            ],
                            resources = [self.target_arn]
                        )
                    ]
                )

                # https://www.pulumi.com/registry/packages/aws/api-docs/iam/role/
                event_bus_role = aws.iam.Role(
                    f"{self.name}-Role",
                    inline_policies = [aws.iam.RoleInlinePolicyArgs(
                        name = f"{self.name}-PutEventBus",
                        policy = event_bus_policy.json
                    )],
                    assume_role_policy = assume_role_policy.json
                )

                # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
                aws.cloudwatch.EventTarget(
                    f"{self.name}-RuleTarget",
                    arn = self.target_arn,
                    event_bus_name = self.event_bus_name,
                    rule = rule.name,
                    role_arn = event_bus_role,
                    input_transformer = input_transformer,
                    retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                        maximum_event_age_in_seconds = self.max_event_age_seconds,
                        maximum_retry_attempts = self.max_retry_attempts
                    ),
                    opts = pulumi.ResourceOptions(parent=rule)
                )

                pulumi.export(f"{self.name}-iam-role-arn", event_bus_role.arn)

            else:
                # Additional Logic for API Destination as a Target
                print("API Destination Target --> Creating IAM Role")
                print("API Destination Target --> Adding Invoke API Permission")

                assume_role_policy = aws.iam.get_policy_document(statements=[
                    aws.iam.GetPolicyDocumentStatementArgs(
                        actions = ["sts:AssumeRole"],
                        principals = [aws.iam.GetPolicyDocumentStatementPrincipalArgs(
                            type = "Service",
                            identifiers = ["events.amazonaws.com"],
                        )],
                    )]
                )

                # https://www.pulumi.com/registry/packages/aws/api-docs/iam/getpolicydocument/
                api_destination_policy = aws.iam.get_policy_document(
                    statements = [
                        aws.iam.GetPolicyDocumentStatementArgs(
                            actions = [
                                "events:InvokeApiDestination"
                            ],
                            resources = [self.target_arn]
                        )
                    ]
                )

                # https://www.pulumi.com/registry/packages/aws/api-docs/iam/role/
                destination_role = aws.iam.Role(
                    f"{self.name}Role",
                    inline_policies = [aws.iam.RoleInlinePolicyArgs(
                        name = f"{self.name}-InvokeApiDestination",
                        policy = api_destination_policy.json
                    )],
                    assume_role_policy = assume_role_policy.json
                )

                # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
                aws.cloudwatch.EventTarget(
                    f"{self.name}RuleTarget",
                    arn = self.target_arn,
                    event_bus_name = self.event_bus_name,
                    rule = rule.name,
                    role_arn = destination_role,
                    input_transformer = input_transformer,
                    retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                        maximum_event_age_in_seconds = self.max_event_age_seconds,
                        maximum_retry_attempts = self.max_retry_attempts
                    ),
                    opts = pulumi.ResourceOptions(parent=rule)
                )

                pulumi.export(f"{self.name}-iam-role-arn", destination_role.arn)

        def create_step_function_event():
            # Additional Logic for Lambda as a Target
            print("Step Function Target --> Invoke State Machine")

            assume_role_policy = aws.iam.get_policy_document(statements=[
                aws.iam.GetPolicyDocumentStatementArgs(
                    actions = ["sts:AssumeRole"],
                    principals = [aws.iam.GetPolicyDocumentStatementPrincipalArgs(
                        type = "Service",
                        identifiers = ["events.amazonaws.com"],
                    )],
                )]
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/iam/getpolicydocument/
            step_function_policy = aws.iam.get_policy_document(
                statements = [
                    aws.iam.GetPolicyDocumentStatementArgs(
                        actions = [
                            "states:StartExecution"
                        ],
                        resources = [self.target_arn]
                    )
                ]
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/iam/role/
            step_function_role = aws.iam.Role(
                f"{self.name}Role",
                inline_policies = [aws.iam.RoleInlinePolicyArgs(
                    name = f"{self.name}-InvokeStepFunction",
                    policy = step_function_policy.json
                )],
                assume_role_policy = assume_role_policy.json
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
            aws.cloudwatch.EventTarget(
                f"{self.name}RuleTarget",
                arn = self.target_arn,
                event_bus_name = self.event_bus_name,
                rule = rule.name,
                role_arn = step_function_role,
                input_transformer = input_transformer,
                retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                    maximum_event_age_in_seconds = self.max_event_age_seconds,
                    maximum_retry_attempts = self.max_retry_attempts
                ),
                opts = pulumi.ResourceOptions(parent=rule)
            )

            pulumi.export(f"{self.name}-iam-role-arn", step_function_role.arn)

        def create_kinesis_stream_event():
            # Additional Logic for Kinesis Stream as a Target
            print("Kinesis Stream Target --> Put Record on Kinesis Stream")

            assume_role_policy = aws.iam.get_policy_document(statements=[
                aws.iam.GetPolicyDocumentStatementArgs(
                    actions = ["sts:AssumeRole"],
                    principals = [aws.iam.GetPolicyDocumentStatementPrincipalArgs(
                        type = "Service",
                        identifiers = ["events.amazonaws.com"],
                    )],
                )]
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/iam/getpolicydocument/
            kinesis_stream_policy = aws.iam.get_policy_document(
                statements = [
                    aws.iam.GetPolicyDocumentStatementArgs(
                        actions = [
                            "kinesis:PutRecord"
                        ],
                        resources = [self.target_arn]
                    )
                ]
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/iam/role/
            kinesis_role = aws.iam.Role(
                f"{self.name}Role",
                inline_policies = [aws.iam.RoleInlinePolicyArgs(
                    name = f"{self.name}-InvokePutRecordStream",
                    policy = kinesis_stream_policy.json
                )],
                assume_role_policy = assume_role_policy.json
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
            aws.cloudwatch.EventTarget(
                f"{self.name}RuleTarget",
                arn = self.target_arn,
                event_bus_name = self.event_bus_name,
                rule = rule.name,
                role_arn = kinesis_role,
                input_transformer = input_transformer,
                retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                    maximum_event_age_in_seconds = self.max_event_age_seconds,
                    maximum_retry_attempts = self.max_retry_attempts
                ),
                opts = pulumi.ResourceOptions(parent=rule)
            )

            pulumi.export(f"{self.name}-iam-role-arn", kinesis_role.arn)

        def create_queue_event():
            # Additional Logic for Lambda as a Target
            print("SQS Target --> Send Message to Queue")

            assume_role_policy = aws.iam.get_policy_document(statements=[
                aws.iam.GetPolicyDocumentStatementArgs(
                    actions = ["sts:AssumeRole"],
                    principals = [aws.iam.GetPolicyDocumentStatementPrincipalArgs(
                        type = "Service",
                        identifiers = ["events.amazonaws.com"],
                    )],
                )]
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/iam/getpolicydocument/
            queue_policy = aws.iam.get_policy_document(
                statements=[
                    aws.iam.GetPolicyDocumentStatementArgs(
                        actions = [
                            "sqs:SendMessage"
                        ],
                        resources = [self.target_arn],
                        conditions = [aws.iam.GetPolicyDocumentStatementConditionArgs(
                            test = "ArnEquals",
                            variable = "aws:SourceArn",
                            values = [rule.arn],
                        )],
                    )
                ]
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/iam/role/
            queue_role = aws.iam.Role(
                f"{self.name}Role",
                inline_policies = [aws.iam.RoleInlinePolicyArgs(
                    name = f"{self.name}-InvokeStepFunction",
                    policy = queue_policy.json
                )],
                assume_role_policy = assume_role_policy.json
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
            aws.cloudwatch.EventTarget(
                f"{self.name}RuleTarget",
                arn = self.target_arn,
                event_bus_name = self.event_bus_name,
                rule = rule.name,
                role_arn = queue_role,
                input_transformer = input_transformer,
                retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                    maximum_event_age_in_seconds = self.max_event_age_seconds,
                    maximum_retry_attempts = self.max_retry_attempts
                ),
                opts = pulumi.ResourceOptions(parent=rule)
            )

            pulumi.export(f"{self.name}-iam-role-arn", queue_role.arn)

        # Conditional add a Cloudwatch Log group and output events to it
        # This is typically only recommended for troubleshooting and not
        # recommended to be on all the time and defaults to only keeping
        # days worth as there can be issues with logging sensitive data.
        if self.log_group:
            # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/loggroup/
            print("Logs Target --> Creating Cloudwatch Log Group")

            log_group = aws.cloudwatch.LogGroup(
                f"/aws/events/{self.name}-logs",
                retention_in_days = 1
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
            aws.cloudwatch.EventTarget(
                f"{self.name}-LogsRuleTarget",
                arn = log_group.arn,
                event_bus_name = self.event_bus_name,
                rule = rule.name,
                input_transformer = input_transformer,
                retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                    maximum_event_age_in_seconds = self.max_event_age_seconds,
                    maximum_retry_attempts = self.max_retry_attempts
                ),
                opts = pulumi.ResourceOptions(parent=log_group)
            )

            pulumi.export(f"{self.name}-logs-arn", log_group.arn)

        # Dictionary used to figure out what type of event and what needs to be run
        event_dict = {
            "lambda": create_lambda_event,
            "events": create_events_event,
            "states": create_step_function_event,
            "kinesis": create_kinesis_stream_event,
            "sqs": create_queue_event
        }

        event_dict.get(self.resource_type, general_event)()
