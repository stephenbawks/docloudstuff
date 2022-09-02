# pylint: disable=unused-variable, too-many-arguments

"""
Do Cloud Stuff - Events module
"""
import json
from typing import Optional
import pulumi
import pulumi_aws as aws
import pulumi_aws_native as aws_native


class Events:
    """
    Do Cloud Stuff - Events Module
    """

    @staticmethod
    def _dict_to_json(value: dict, value_name: str) -> str:
        print(f"You entered a dictionary for {value_name} an it should have been a string. Converting it for you.")
        return json.dumps(value)

    @staticmethod
    def _is_json(json_to_check: str) -> bool:
        try:
            json.loads(json_to_check)
            # the string appears to be valid JSON, return True
        except ValueError as json_error:
            print("The string you specified does not appear to be a valid JSON encoded string.")
            return False
            # the string does not appear to be valid JSON, return False
        return True

    @staticmethod
    def _is_dict(dict_to_check: dict) -> bool:
        try:
            isinstance(dict_to_check, dict)
            # the string appears to be valid JSON, return True
        except ValueError as dict_error:
            print("The input you specified does not appear to be a valid dictionary.")
            return False
            # the string does not appear to be valid JSON, return False
        return True


    @classmethod
    def create_bus(cls, name: str,
        event_archive: Optional[bool] = False,
        archive_days: Optional[int] = 7,
        archive_event_pattern: Optional[dict] = None,
        schema_discoverer: Optional[bool] = False
    ):
        """
        Creates an Eventbridge Event Bus
        Optionally creates an Event Archive and or an Event Schema Discoverer

        Args:
            name (str): Unique name that is pre-prended to name resources
            event_archive (Optional[bool]): Optioanally create an Event Archive. Defaults to False.
            archive_days (Optional[int]): If creating an event archive, how many days to retain messages for. Defaults to 7.
            archive_event_pattern (Optional[str]): An event pattern to use to filter events sent to the archive. Defaults to None.
            schema_discoverer (Optional[bool]): Optionally create a Schema Discoverer for the event bus. Defaults to False.

        Raises:
            ValueError: Days for retention must be greater than or equal to 0
        """

        if event_archive and event_archive < 0:
            # If intending to create an event archive check to make sure days is not less than zero
            raise ValueError("Days for Archive Retention must be greater than or equal to 0 (zero).")
        if event_archive and event_archive == 0:
            # if intending to create an archive, warn if days is equal to zero
            print("You enterd 0 (zero) for the amount of days to retain messages in the archive. This will result in events being stored indefinitely so use caution.")

        # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventbus/
        bus = aws.cloudwatch.EventBus(f"{name}-bus")

        pulumi.export(f"{name}-bus-arn", bus.arn)

        if event_archive:
            if isinstance(archive_event_pattern, dict):
                # Checking to see if the archive pattern was sent as a dict, if so dump to string
                print("The archive event pattern is a dictionary and will be converted to a string.")
                archive_event_pattern = json.dumps(archive_event_pattern)

            event_archive = aws_native.events.Archive(f"{name}-event-archive",
                description=f"Archived events from {name}-bus",
                event_source_arn=bus.arn,
                retention_days=archive_days,
                event_pattern=archive_event_pattern,
                opts = pulumi.ResourceOptions(parent=bus)
            )

            pulumi.export(f"{name}-event-archive-arn", event_archive.arn)

        if schema_discoverer:
            # https://www.pulumi.com/registry/packages/aws/api-docs/schemas/discoverer/
            bus_schema_discoverer = aws.schemas.Discoverer(f"{name}-schema-discoverer",
                source_arn=bus.arn,
                description=f"Schema Discover for the {name}-bus",
            )

            pulumi.export(f"{name}-schema-discoverer-arn", bus_schema_discoverer.arn)


    @classmethod
    def create_rule_target(cls,
        name: str,
        event_pattern: str,
        target_arn: str,
        description: Optional[str] = None,
        event_bus_name: Optional[str] = "default",
        input_paths: Optional[dict[str, str]] = None,
        input_template: Optional[str] = None,
        max_retry_attempts: Optional[int] = 185,
        max_event_age_seconds: Optional[int] = 86400,
        optional_log_group: Optional[bool] = False,
    ):
        """
            Creates an Eventbridge Rule and attaches a target
            Adds addtional resources depending on the target

        Args:
            name (str): Unique name that is pre-prended to name resources
            event_pattern (str): The event pattern described a JSON object.
            target_arn (str): The ARN of the target that events will be sent to.
            description (Optional[str]): The description of the rule.
            event_bus_name (Optional[str]): The event bus to associate with this rule. If you omit this, the default event bus is used.
            input_paths (Optional[dict[str, str]]): Key value pairs specified in the form of JSONPath (for example, time = $.time)
            input_template (Optional[str]): Template to customize data sent to the target. Must be valid JSON. To send a string value, the string value must include double quotes.
            optional_log_group (Optional[bool]): True or False.  If True, this will create a Cloudwatch Log group that can be used to troubleshoot event data.  Ideally used for debug and troubleshooting.

        """

        resource_name = aws.get_arn(arn=target_arn).resource
        resource_type = aws.get_arn(arn=target_arn).service

        # If the event is being transformed, there are two variables that are required
        # `input_paths` and `input_template`
        if input_paths and input_template:
            if Events._is_json(json_to_check=input_template) and Events._is_dict(dict_to_check=input_paths):
                # Checking to also see if input_template is a valid json string
                input_transformer = aws.cloudwatch.EventTargetInputTransformerArgs(
                    input_paths = input_paths,
                    input_template = input_template
                )
        else:
            input_transformer = None

        if isinstance(event_pattern, dict):
            # Check to see if the event pattern was sent as a dictionary
            # If so, do a json dump to string
            event_pattern = Events._dict_to_json(value=event_pattern, value_name="event_pattern")

        # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventrule/
        rule = aws.cloudwatch.EventRule(
            f"{name}-EventRule",
            name = name,
            description = description,
            event_bus_name = event_bus_name,
            is_enabled = True,
            event_pattern = event_pattern
        )

        pulumi.export(f"{name}-rule-arn", rule.arn)


        def general_event():
            # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
            aws.cloudwatch.EventTarget(
                f"{name}-RuleTarget",
                arn = target_arn,
                event_bus_name = event_bus_name,
                rule = rule.name,
                input_transformer = input_transformer,
                retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                    maximum_event_age_in_seconds = max_event_age_seconds,
                    maximum_retry_attempts = max_retry_attempts
                ),
                opts = pulumi.ResourceOptions(parent=rule)
            )

        def create_lambda_event():
            # Additional Logic for Lambda as a Target
            print("Lambda Target --> Adding Lambda Invoke Permission")

            # https://www.pulumi.com/registry/packages/aws/api-docs/lambda/permission/
            aws.lambda_.Permission(
                f"{name}-LambdaPermission",
                action = "lambda:InvokeFunction",
                function = resource_name,
                principal = "events.amazonaws.com",
                source_arn = rule.arn,
                opts = pulumi.ResourceOptions(parent=rule)
            )

            aws.cloudwatch.EventTarget(
                f"{name}-RuleTarget",
                arn = target_arn,
                event_bus_name = event_bus_name,
                rule = rule.arn,
                input_transformer = input_transformer,
                retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                    maximum_event_age_in_seconds = max_event_age_seconds,
                    maximum_retry_attempts = max_retry_attempts
                ),
                opts = pulumi.ResourceOptions(parent=rule)
            )

        def create_events_event():

            # This could be an API Destination or trying to send to another Eventbridge
            if resource_name.startswith("event-bus"):
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
                            resources = [target_arn]
                        )
                    ]
                )

                # https://www.pulumi.com/registry/packages/aws-native/api-docs/iam/role/
                event_bus_role = aws_native.iam.Role(
                    f"{name}-Role",
                    policies = [aws_native.iam.RolePolicyArgs(
                        policy_name = f"{name}-PutEventBus",
                        policy_document = event_bus_policy.json
                    )],
                    assume_role_policy_document = assume_role_policy.json
                )

                # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
                aws.cloudwatch.EventTarget(
                    f"{name}-RuleTarget",
                    arn = target_arn,
                    event_bus_name = event_bus_name,
                    rule = rule.name,
                    role_arn = event_bus_role.arn,
                    input_transformer = input_transformer,
                    retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                        maximum_event_age_in_seconds = max_event_age_seconds,
                        maximum_retry_attempts = max_retry_attempts
                    ),
                    opts = pulumi.ResourceOptions(parent=rule)
                )

                pulumi.export(f"{name}-iam-role-arn", event_bus_role.arn)

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
                            resources = [target_arn]
                        )
                    ]
                )

                # https://www.pulumi.com/registry/packages/aws-native/api-docs/iam/role/
                destination_role = aws_native.iam.Role(
                    f"{name}-Role",
                    policies = [aws_native.iam.RolePolicyArgs(
                        policy_name = f"{name}-InvokeApiDestination",
                        policy_document = api_destination_policy.json
                    )],
                    assume_role_policy_document = assume_role_policy.json
                )

                # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
                aws.cloudwatch.EventTarget(
                    f"{name}RuleTarget",
                    arn = target_arn,
                    event_bus_name = event_bus_name,
                    rule = rule.name,
                    role_arn = destination_role.arn,
                    input_transformer = input_transformer,
                    retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                        maximum_event_age_in_seconds = max_event_age_seconds,
                        maximum_retry_attempts = max_retry_attempts
                    ),
                    opts = pulumi.ResourceOptions(parent=rule)
                )

                pulumi.export(f"{name}-iam-role-arn", destination_role.arn)

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
                        resources = [target_arn]
                    )
                ]
            )

            # https://www.pulumi.com/registry/packages/aws-native/api-docs/iam/role/
            step_function_role = aws_native.iam.Role(
                f"{name}-Role",
                policies = [aws_native.iam.RolePolicyArgs(
                    policy_name = f"{name}-InvokeStepFunction",
                    policy_document = step_function_policy.json
                )],
                assume_role_policy_document = assume_role_policy.json
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
            aws.cloudwatch.EventTarget(
                f"{name}-RuleTarget",
                arn = target_arn,
                event_bus_name = event_bus_name,
                rule = rule.name,
                role_arn = step_function_role.arn,
                input_transformer = input_transformer,
                retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                    maximum_event_age_in_seconds = max_event_age_seconds,
                    maximum_retry_attempts = max_retry_attempts
                ),
                opts = pulumi.ResourceOptions(parent=rule)
            )

            pulumi.export(f"{name}-iam-role-arn", step_function_role.arn)

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
                        resources = [target_arn]
                    )
                ]
            )

            # https://www.pulumi.com/registry/packages/aws-native/api-docs/iam/role/
            kinesis_role = aws_native.iam.Role(
                f"{name}-Role",
                policies = [aws_native.iam.RolePolicyArgs(
                    policy_name = f"{name}-InvokePutRecordStream",
                    policy_document = kinesis_stream_policy.json
                )],
                assume_role_policy_document = assume_role_policy.json
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
            aws.cloudwatch.EventTarget(
                f"{name}RuleTarget",
                arn = target_arn,
                event_bus_name = event_bus_name,
                rule = rule.name,
                role_arn = kinesis_role.arn,
                input_transformer = input_transformer,
                retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                    maximum_event_age_in_seconds = max_event_age_seconds,
                    maximum_retry_attempts = max_retry_attempts
                ),
                opts = pulumi.ResourceOptions(parent=rule)
            )

            pulumi.export(f"{name}-iam-role-arn", kinesis_role.arn)

        def create_queue_event():
            # Additional Logic for Lambda as a Target
            print("SQS Target --> Adding Queue Policy")

            queue_url = aws.sqs.get_queue(name=resource_name).url

            # https://www.pulumi.com/registry/packages/aws/api-docs/iam/getpolicydocument/
            queue_policy = aws.iam.get_policy_document(
                statements=[
                    aws.iam.GetPolicyDocumentStatementArgs(
                        actions = [
                            "sqs:SendMessage"
                        ],
                        principals=[
                            aws.iam.GetPolicyDocumentStatementPrincipalArgs(
                                type="Service",
                                identifiers=["events.amazonaws.com"],
                            )
                        ],
                        resources = [target_arn],
                        conditions = [aws.iam.GetPolicyDocumentStatementConditionArgs(
                            test = "ArnEquals",
                            variable = "aws:SourceArn",
                            values = [rule.arn],
                        )],
                    )
                ]
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/sqs/queuepolicy/
            aws.sqs.QueuePolicy(
                f"{name}-queue-policy",
                queue_url=queue_url,
                policy=queue_policy.json,
                opts = pulumi.ResourceOptions(parent=rule)
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
            aws.cloudwatch.EventTarget(
                f"{name}-RuleTarget",
                arn = target_arn,
                event_bus_name = event_bus_name,
                rule = rule.name,
                input_transformer = input_transformer,
                retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                    maximum_event_age_in_seconds = max_event_age_seconds,
                    maximum_retry_attempts = max_retry_attempts
                ),
                opts = pulumi.ResourceOptions(parent=rule)
            )

        # Conditional add a Cloudwatch Log group and output events to it
        # This is typically only recommended for troubleshooting and not
        # recommended to be on all the time and defaults to only keeping
        # days worth as there can be issues with logging sensitive data.
        if optional_log_group:
            # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/loggroup/
            print("Logs Target --> Creating Cloudwatch Log Group")

            # https://www.pulumi.com/registry/packages/aws-native/api-docs/logs/loggroup/
            log_group = aws_native.cloudwatch.LogGroup(
                f"{name}-logs",
                log_group_name = f"/aws/events/{name}-logs",
                retention_in_days = 1
            )

            # https://www.pulumi.com/registry/packages/aws/api-docs/cloudwatch/eventtarget/
            aws.cloudwatch.EventTarget(
                f"{name}-LogsRuleTarget",
                arn = log_group.arn,
                event_bus_name = event_bus_name,
                rule = rule.name,
                input_transformer = input_transformer,
                retry_policy = aws.cloudwatch.EventTargetRetryPolicyArgs(
                    maximum_event_age_in_seconds = max_event_age_seconds,
                    maximum_retry_attempts = max_retry_attempts
                ),
                opts = pulumi.ResourceOptions(parent=log_group)
            )

            pulumi.export(f"{name}-logs-arn", log_group.arn)

        # Dictionary used to figure out what type of event and what needs to be run
        event_dict = {
            "lambda": create_lambda_event,
            "events": create_events_event,
            "states": create_step_function_event,
            "kinesis": create_kinesis_stream_event,
            "sqs": create_queue_event
        }

        event_dict.get(resource_type, general_event)()
