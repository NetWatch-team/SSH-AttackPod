[
    {
        "name": "${ECS_TASK_DEFINITION_NAME}",
        "image": "${IMAGE}",
        "cpu": ${CPU},
        "memory": ${MEMORY},
        "portMappings": [
            {
              "containerPort" : ${NETWATCH_PORT},
              "hostPort" : ${NETWATCH_PORT},
              "protocol" : "tcp"
            }
        ],
        "essential": true,
        "environment": [
            {
                "name": "NETWATCH_COLLECTOR_URL",
                "value": "${NETWATCH_COLLECTOR_URL}"
            },
            {
                "name": "NETWATCH_TEST_MODE",
                "value": "${NETWATCH_TEST_MODE}"
            },
            {
                "name": "NETWATCH_PORT",
                "value": "${NETWATCH_PORT}"
            }
        ],
        "secrets": [
            {
                "name": "NETWATCH_COLLECTOR_AUTHORIZATION",
                "valueFrom": "${NETWATCH_COLLECTOR_AUTHORIZATION}"
            }
        ],
        "mountPoints": [],
        "volumesFrom": [],
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-create-group": "true",
                "awslogs-group": "${CLOUDWATCH_LOGROUP_NAME}",
                "awslogs-region": "${AWS_REGION}",
                "awslogs-stream-prefix": "ecs"
            }
        }
    }
]